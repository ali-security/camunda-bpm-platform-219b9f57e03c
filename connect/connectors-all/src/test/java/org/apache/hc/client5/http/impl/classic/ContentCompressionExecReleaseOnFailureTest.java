/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH
 * under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership. Camunda licenses this file to you under the Apache License,
 * Version 2.0; you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hc.client5.http.impl.classic;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.hc.client5.http.HttpRoute;
import org.apache.hc.client5.http.classic.ExecChain;
import org.apache.hc.client5.http.classic.ExecRuntime;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.entity.DecompressingEntity;
import org.apache.hc.client5.http.entity.EntityBuilder;
import org.apache.hc.client5.http.impl.ChainElement;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.Method;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.apache.hc.core5.util.Timeout;
import org.camunda.connect.ConnectorRequestException;
import org.camunda.connect.httpclient.HttpResponse;
import org.camunda.connect.httpclient.impl.HttpConnectorImpl;
import org.junit.Before;
import org.junit.Test;

/**
 * Regression tests for CVE-2026-64607 (GHSA-hjcp-jmpx-g3qm) in the shaded httpclient5
 * {@link ContentCompressionExec}: when handling the response content coding fails (an
 * unsupported {@code Content-Encoding}, or a runtime failure while inspecting the response
 * entity), the response must be closed so that the underlying connection is released instead of
 * staying leased forever. Otherwise a remote server (for example one called by the HTTP
 * connector) can exhaust the client's connection pool.
 *
 * @see <a href="https://github.com/advisories/GHSA-hjcp-jmpx-g3qm">GHSA-hjcp-jmpx-g3qm</a>
 */
public class ContentCompressionExecReleaseOnFailureTest {

  private static final HttpHost HOST = new HttpHost("somehost", 80);

  private static final String UNSUPPORTED_ENCODING_RESPONSE = "HTTP/1.1 200 OK\r\n"
      + "Content-Type: text/plain\r\n"
      + "Content-Encoding: x-unsupported\r\n"
      + "Content-Length: 2\r\n"
      + "Connection: close\r\n"
      + "\r\n"
      + "ok";

  private ClassicHttpRequest request;
  private ExecChain.Scope scope;

  @Before
  public void setUp() {
    request = new BasicClassicHttpRequest(Method.GET, HOST, "/");
    scope = new ExecChain.Scope("test", new HttpRoute(HOST), request, unusedExecRuntime(), HttpClientContext.create());
  }

  @Test
  public void testUnknownContentEncodingClosesResponse() throws Exception {
    final CloseTrackingResponse response = new CloseTrackingResponse();
    response.setEntity(EntityBuilder.create().setText("encoded stuff").setContentEncoding("whatever").build());
    final ContentCompressionExec impl = new ContentCompressionExec(false);

    final HttpException ex = assertThrows(HttpException.class,
        () -> impl.execute(request, scope, (req, sc) -> response));
    assertEquals("Unsupported Content-Encoding: whatever", ex.getMessage());
    assertEquals(1, response.closeCount);
  }

  @Test
  public void testRuntimeExceptionClosesResponse() throws Exception {
    final CloseTrackingResponse response = new CloseTrackingResponse();
    final AtomicInteger entityCloseCount = new AtomicInteger();
    response.setEntity(entityFailingOnContentEncoding(new IllegalStateException("Boom"), entityCloseCount));
    final ContentCompressionExec impl = new ContentCompressionExec();

    final IllegalStateException ex = assertThrows(IllegalStateException.class,
        () -> impl.execute(request, scope, (req, sc) -> response));
    assertEquals("Boom", ex.getMessage());
    assertEquals(1, response.closeCount);
    assertEquals(1, entityCloseCount.get());
  }

  @Test
  public void testSupportedContentEncodingKeepsResponseOpen() throws Exception {
    final CloseTrackingResponse response = new CloseTrackingResponse();
    response.setEntity(EntityBuilder.create().setText("encoded stuff").setContentEncoding("gzip").build());
    final ContentCompressionExec impl = new ContentCompressionExec(false);

    assertSame(response, impl.execute(request, scope, (req, sc) -> response));
    assertTrue(response.getEntity() instanceof DecompressingEntity);
    assertEquals(0, response.closeCount);
  }

  @Test
  public void testIgnoredUnknownContentEncodingKeepsResponseOpen() throws Exception {
    final CloseTrackingResponse response = new CloseTrackingResponse();
    final HttpEntity original = EntityBuilder.create().setText("encoded stuff").setContentEncoding("whatever").build();
    response.setEntity(original);
    final ContentCompressionExec impl = new ContentCompressionExec();

    assertSame(response, impl.execute(request, scope, (req, sc) -> response));
    assertSame(original, response.getEntity());
    assertEquals(0, response.closeCount);
  }

  @Test
  public void testConnectorReleasesConnectionOnUnsupportedContentEncoding() throws Exception {
    final PoolingHttpClientConnectionManager connManager = PoolingHttpClientConnectionManagerBuilder.create()
        .setMaxConnTotal(1)
        .setMaxConnPerRoute(1)
        .build();
    final CloseableHttpClient client = HttpClients.custom()
        .setConnectionManager(connManager)
        .replaceExecInterceptor(ChainElement.COMPRESS.name(), new ContentCompressionExec(false))
        .setDefaultRequestConfig(RequestConfig.custom()
            .setConnectionRequestTimeout(Timeout.ofSeconds(2))
            .build())
        .build();
    final HttpConnectorImpl connector = new HttpConnectorImpl();
    connector.getHttpClient().close();
    connector.setHttpClient(client);

    try (CannedResponseServer server = new CannedResponseServer(UNSUPPORTED_ENCODING_RESPONSE)) {
      // with a single pooled connection, a leaked connection makes every later request time out
      // waiting for a connection instead of failing on the content coding again
      for (int i = 0; i < 3; i++) {
        final ConnectorRequestException ex = assertThrows(ConnectorRequestException.class,
            () -> connector.createRequest().url(server.url()).get().execute());
        assertCausedByUnsupportedContentEncoding(ex);
        assertEquals("connections still leased after request " + i, 0, connManager.getTotalStats().getLeased());
      }
    } finally {
      client.close();
    }
  }

  @Test
  public void testConnectorReleasesConnectionOnSuccess() throws Exception {
    final PoolingHttpClientConnectionManager connManager = PoolingHttpClientConnectionManagerBuilder.create()
        .setMaxConnTotal(1)
        .setMaxConnPerRoute(1)
        .build();
    final CloseableHttpClient client = HttpClients.custom()
        .setConnectionManager(connManager)
        .replaceExecInterceptor(ChainElement.COMPRESS.name(), new ContentCompressionExec(false))
        .build();
    final HttpConnectorImpl connector = new HttpConnectorImpl();
    connector.getHttpClient().close();
    connector.setHttpClient(client);

    try (CannedResponseServer server = new CannedResponseServer(UNSUPPORTED_ENCODING_RESPONSE
        .replace("Content-Encoding: x-unsupported\r\n", "Content-Encoding: identity\r\n"))) {
      final HttpResponse response = connector.createRequest().url(server.url()).get().execute();
      try {
        assertEquals(Integer.valueOf(200), response.getStatusCode());
        assertEquals("ok", response.getResponse());
      } finally {
        response.close();
      }
      assertEquals(0, connManager.getTotalStats().getLeased());
    } finally {
      client.close();
    }
  }

  private static void assertCausedByUnsupportedContentEncoding(final Throwable thrown) {
    Throwable cause = thrown;
    while (cause != null && !(cause instanceof HttpException)) {
      cause = cause.getCause();
    }
    assertNotNull("expected an HttpException in the cause chain of " + thrown, cause);
    assertEquals("Unsupported Content-Encoding: x-unsupported", cause.getMessage());
  }

  private static ExecRuntime unusedExecRuntime() {
    return (ExecRuntime) Proxy.newProxyInstance(ExecRuntime.class.getClassLoader(), new Class<?>[] {ExecRuntime.class},
        (proxy, method, args) -> {
          switch (method.getName()) {
            case "hashCode":
              return System.identityHashCode(proxy);
            case "equals":
              return proxy == args[0];
            case "toString":
              return "UnusedExecRuntime";
            default:
              throw new UnsupportedOperationException(method.getName());
          }
        });
  }

  private static HttpEntity entityFailingOnContentEncoding(final RuntimeException failure,
                                                           final AtomicInteger closeCount) {
    return (HttpEntity) Proxy.newProxyInstance(HttpEntity.class.getClassLoader(), new Class<?>[] {HttpEntity.class},
        (proxy, method, args) -> {
          switch (method.getName()) {
            case "getContentLength":
              return -1L;
            case "getContentEncoding":
              throw failure;
            case "close":
              closeCount.incrementAndGet();
              return null;
            case "isRepeatable":
            case "isStreaming":
            case "isChunked":
              return false;
            case "hashCode":
              return System.identityHashCode(proxy);
            case "equals":
              return proxy == args[0];
            case "toString":
              return "EntityFailingOnContentEncoding";
            default:
              return null;
          }
        });
  }

  private static final class CloseTrackingResponse extends BasicClassicHttpResponse {

    private static final long serialVersionUID = 1L;

    private int closeCount;

    CloseTrackingResponse() {
      super(200, "OK");
    }

    @Override
    public void close() throws IOException {
      closeCount++;
      super.close();
    }
  }

}
