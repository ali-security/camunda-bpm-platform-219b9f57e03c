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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.hc.client5.http.ClientProtocolException;
import org.apache.hc.client5.http.HttpRoute;
import org.apache.hc.client5.http.classic.ExecChainHandler;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.ConnectionEndpoint;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.io.LeaseRequest;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.impl.io.HttpRequestExecutor;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.junit.Before;
import org.junit.Test;

/**
 * Regression tests for CVE-2026-64607 (GHSA-hjcp-jmpx-g3qm) in the shaded httpclient5
 * {@link InternalHttpClient}: when the classic execution chain fails after a connection endpoint
 * has been leased (for example a decoding failure in a handler above the transport), the
 * endpoint must be discarded and handed back to the connection manager. Otherwise every such
 * failure leaks a pooled connection until the pool is exhausted.
 *
 * @see <a href="https://github.com/advisories/GHSA-hjcp-jmpx-g3qm">GHSA-hjcp-jmpx-g3qm</a>
 */
public class InternalHttpClientReleaseOnFailureTest {

  private static final String FAILURE_HEADER = "X-Fail";

  private static final String OK_RESPONSE = "HTTP/1.1 200 OK\r\n"
      + "Content-Type: text/plain\r\n"
      + "Content-Length: 2\r\n"
      + "Connection: close\r\n"
      + "\r\n"
      + "ok";

  private HttpRoute route;
  private FakeEndpoint endpoint;
  private List<Object[]> releases;
  private HttpClientConnectionManager connManager;

  @Before
  public void setUp() {
    route = new HttpRoute(new HttpHost("somehost", 80));
    endpoint = new FakeEndpoint();
    releases = new CopyOnWriteArrayList<>();
    connManager = fakeConnectionManager(endpoint, releases);
  }

  @Test
  public void testExecuteHttpExceptionDiscardsEndpoint() throws Exception {
    final InternalHttpClient client = client(acquireEndpointThenFail(new HttpException("Ooopsie")));

    assertThrows(ClientProtocolException.class,
        () -> client.execute(new HttpGet("http://somehost/stuff"), response -> null));

    assertEndpointDiscarded();
  }

  @Test
  public void testExecuteIOExceptionDiscardsEndpoint() throws Exception {
    final InternalHttpClient client = client(acquireEndpointThenFail(new IOException("Ooopsie")));

    final IOException ex = assertThrows(IOException.class,
        () -> client.execute(new HttpGet("http://somehost/stuff"), response -> null));
    assertEquals("Ooopsie", ex.getMessage());

    assertEndpointDiscarded();
  }

  @Test
  public void testExecuteRuntimeExceptionDiscardsEndpoint() throws Exception {
    final InternalHttpClient client = client(acquireEndpointThenFail(new IllegalStateException("Ooopsie")));

    final IllegalStateException ex = assertThrows(IllegalStateException.class,
        () -> client.execute(new HttpGet("http://somehost/stuff"), response -> null));
    assertEquals("Ooopsie", ex.getMessage());

    assertEndpointDiscarded();
  }

  @Test
  public void testSuccessfulExecutionKeepsEndpoint() throws Exception {
    final ClassicHttpResponse original = new BasicClassicHttpResponse(200, "OK");
    final InternalHttpClient client = client((request, scope, chain) -> {
      scope.execRuntime.acquireEndpoint("test", route, null, scope.clientContext);
      return original;
    });

    final Integer handled = client.execute(new HttpGet("http://somehost/stuff"), response -> response.getCode());

    assertEquals(Integer.valueOf(200), handled);
    assertTrue(endpoint.closeModes.isEmpty());
    assertTrue(releases.isEmpty());
  }

  @Test
  public void testPooledConnectionReleasedWhenExecChainFails() throws Exception {
    final PoolingHttpClientConnectionManager pool = PoolingHttpClientConnectionManagerBuilder.create()
        .setMaxConnTotal(1)
        .setMaxConnPerRoute(1)
        .build();
    // fails after the transport returned the response, without closing it, the way a handler
    // failing to process the response content would
    final ExecChainHandler failAfterResponse = (request, scope, chain) -> {
      final ClassicHttpResponse response = chain.proceed(request, scope);
      final Header failure = request.getFirstHeader(FAILURE_HEADER);
      if (failure == null) {
        return response;
      }
      switch (failure.getValue()) {
        case "io":
          throw new IOException("Ooopsie");
        case "http":
          throw new HttpException("Ooopsie");
        default:
          throw new IllegalStateException("Ooopsie");
      }
    };
    final CloseableHttpClient client = HttpClients.custom()
        .setConnectionManager(pool)
        .addExecInterceptorFirst("fail-after-response", failAfterResponse)
        .setDefaultRequestConfig(RequestConfig.custom()
            .setConnectionRequestTimeout(Timeout.ofSeconds(2))
            .build())
        .build();

    try (CannedResponseServer server = new CannedResponseServer(OK_RESPONSE)) {
      // with a single pooled connection, a leaked connection makes every later request time out
      // waiting for a connection
      for (int i = 0; i < 2; i++) {
        assertThrows(IOException.class, () -> client.execute(failingGet(server.url(), "io"), response -> null));
        assertEquals("connections leased after IOException", 0, pool.getTotalStats().getLeased());

        assertThrows(ClientProtocolException.class,
            () -> client.execute(failingGet(server.url(), "http"), response -> null));
        assertEquals("connections leased after HttpException", 0, pool.getTotalStats().getLeased());

        assertThrows(IllegalStateException.class,
            () -> client.execute(failingGet(server.url(), "runtime"), response -> null));
        assertEquals("connections leased after RuntimeException", 0, pool.getTotalStats().getLeased());
      }

      final String body = client.execute(new HttpGet(server.url()),
          response -> EntityUtils.toString(response.getEntity(), StandardCharsets.US_ASCII));
      assertEquals("ok", body);
      assertEquals(0, pool.getTotalStats().getLeased());
    } finally {
      client.close();
    }
  }

  private void assertEndpointDiscarded() {
    assertEquals(Collections.singletonList(CloseMode.IMMEDIATE), endpoint.closeModes);
    assertEquals(1, releases.size());
    final Object[] release = releases.get(0);
    assertSame(endpoint, release[0]);
    assertNull(release[1]);
    assertEquals(TimeValue.ZERO_MILLISECONDS, release[2]);
  }

  private InternalHttpClient client(final ExecChainHandler handler) {
    return new InternalHttpClient(
        connManager,
        new HttpRequestExecutor(),
        new ExecChainElement(handler, null),
        (target, context) -> route,
        null,
        null,
        null,
        null,
        HttpClientContext::castOrCreate,
        RequestConfig.DEFAULT,
        null);
  }

  /**
   * Makes the execution chain lease a connection off the exec runtime and then blow up with the
   * given exception, the way a message handler failing mid-exchange would.
   */
  private ExecChainHandler acquireEndpointThenFail(final Exception failure) {
    return (request, scope, chain) -> {
      scope.execRuntime.acquireEndpoint("test", route, null, scope.clientContext);
      if (failure instanceof IOException) {
        throw (IOException) failure;
      }
      if (failure instanceof HttpException) {
        throw (HttpException) failure;
      }
      throw (RuntimeException) failure;
    };
  }

  private static HttpGet failingGet(final String url, final String failure) {
    final HttpGet get = new HttpGet(url);
    get.addHeader(FAILURE_HEADER, failure);
    return get;
  }

  private static HttpClientConnectionManager fakeConnectionManager(final ConnectionEndpoint endpoint,
                                                                   final List<Object[]> releases) {
    final LeaseRequest leaseRequest = (LeaseRequest) Proxy.newProxyInstance(
        LeaseRequest.class.getClassLoader(), new Class<?>[] {LeaseRequest.class},
        (proxy, method, args) -> {
          switch (method.getName()) {
            case "get":
              return endpoint;
            case "cancel":
              return Boolean.TRUE;
            case "hashCode":
              return System.identityHashCode(proxy);
            case "equals":
              return proxy == args[0];
            case "toString":
              return "FakeLeaseRequest";
            default:
              throw new UnsupportedOperationException(method.getName());
          }
        });
    return (HttpClientConnectionManager) Proxy.newProxyInstance(
        HttpClientConnectionManager.class.getClassLoader(), new Class<?>[] {HttpClientConnectionManager.class},
        (proxy, method, args) -> {
          switch (method.getName()) {
            case "lease":
              return leaseRequest;
            case "release":
              releases.add(args);
              return null;
            case "close":
              return null;
            case "hashCode":
              return System.identityHashCode(proxy);
            case "equals":
              return proxy == args[0];
            case "toString":
              return "FakeConnectionManager";
            default:
              throw new UnsupportedOperationException(method.getName());
          }
        });
  }

  private static final class FakeEndpoint extends ConnectionEndpoint {

    private final List<CloseMode> closeModes = new CopyOnWriteArrayList<>();

    @Override
    public ClassicHttpResponse execute(final String id, final ClassicHttpRequest request,
                                       final HttpRequestExecutor executor, final HttpContext context) {
      throw new UnsupportedOperationException("execute");
    }

    @Override
    public boolean isConnected() {
      return false;
    }

    @Override
    public void setSocketTimeout(final Timeout timeout) {
    }

    @Override
    public void close(final CloseMode closeMode) {
      closeModes.add(closeMode);
    }

    @Override
    public void close() {
      closeModes.add(CloseMode.GRACEFUL);
    }
  }

}
