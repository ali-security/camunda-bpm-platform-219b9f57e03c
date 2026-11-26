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
package org.apache.hc.core5.http.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import org.apache.hc.core5.http.MessageConstraintException;
import org.apache.hc.core5.http.RequestHeaderFieldsTooLargeException;
import org.apache.hc.core5.http.impl.io.DefaultHttpRequestParser;
import org.apache.hc.core5.http.impl.io.DefaultHttpResponseParser;
import org.apache.hc.core5.http.impl.io.SessionInputBufferImpl;
import org.camunda.connect.ConnectorRequestException;
import org.camunda.connect.httpclient.HttpResponse;
import org.camunda.connect.httpclient.impl.HttpConnectorImpl;
import org.junit.Test;

/**
 * Regression tests for CVE-2026-54399 (GHSA-hf6x-8p5f-cgmf) in the shaded httpcore5
 * {@link Http1Config}: the HTTP/1.1 message parsers must not accept an unbounded number of
 * header fields or unbounded header lines by default. Otherwise a remote peer (for example a
 * malicious server called by the HTTP connector) can exhaust memory with an oversized response
 * head.
 *
 * @see <a href="https://github.com/advisories/GHSA-hf6x-8p5f-cgmf">GHSA-hf6x-8p5f-cgmf</a>
 */
public class Http1ConfigDefaultsTest {

  private static final int DEFAULT_MAX_HEADER_COUNT = 1024;
  private static final int DEFAULT_MAX_LINE_LENGTH = 8192;

  /** Well above the default header count limit. */
  private static final int EXCESSIVE_HEADER_COUNT = 2000;
  /** Well above the default line length limit. */
  private static final int EXCESSIVE_HEADER_VALUE_LENGTH = 64 * 1024;

  private static final String HEADER_COUNT_EXCEEDED = "Maximum header count exceeded";
  private static final String LINE_LENGTH_EXCEEDED = "Maximum line length limit exceeded";

  @Test
  public void testDefaultConfigLimitsHeaderCountAndLineLength() {
    assertEquals(DEFAULT_MAX_HEADER_COUNT, Http1Config.DEFAULT.getMaxHeaderCount());
    assertEquals(DEFAULT_MAX_LINE_LENGTH, Http1Config.DEFAULT.getMaxLineLength());
  }

  @Test
  public void testBuilderDefaultsLimitHeaderCountAndLineLength() {
    final Http1Config custom = Http1Config.custom().build();
    assertEquals(DEFAULT_MAX_HEADER_COUNT, custom.getMaxHeaderCount());
    assertEquals(DEFAULT_MAX_LINE_LENGTH, custom.getMaxLineLength());

    final Http1Config copy = Http1Config.copy(Http1Config.DEFAULT).build();
    assertEquals(DEFAULT_MAX_HEADER_COUNT, copy.getMaxHeaderCount());
    assertEquals(DEFAULT_MAX_LINE_LENGTH, copy.getMaxLineLength());
  }

  @Test
  public void testExplicitLimitsAreStillHonored() {
    final Http1Config unlimited = Http1Config.custom()
        .setMaxHeaderCount(-1)
        .setMaxLineLength(-1)
        .build();
    assertEquals(-1, unlimited.getMaxHeaderCount());
    assertEquals(-1, unlimited.getMaxLineLength());

    final Http1Config strict = Http1Config.custom()
        .setMaxHeaderCount(10)
        .setMaxLineLength(512)
        .build();
    assertEquals(10, strict.getMaxHeaderCount());
    assertEquals(512, strict.getMaxLineLength());
  }

  @Test
  public void testDefaultResponseParserRejectsExcessiveHeaderCount() {
    final DefaultHttpResponseParser parser = new DefaultHttpResponseParser();
    final SessionInputBufferImpl inBuffer = new SessionInputBufferImpl(Http1Config.DEFAULT.getBufferSize());
    final InputStream inputStream = new ByteArrayInputStream(response(EXCESSIVE_HEADER_COUNT, 0));

    final MessageConstraintException ex = assertThrows(MessageConstraintException.class,
        () -> parser.parse(inBuffer, inputStream));
    assertEquals(HEADER_COUNT_EXCEEDED, ex.getMessage());
  }

  @Test
  public void testDefaultRequestParserRejectsExcessiveHeaderCount() {
    final DefaultHttpRequestParser parser = new DefaultHttpRequestParser();
    final SessionInputBufferImpl inBuffer = new SessionInputBufferImpl(Http1Config.DEFAULT.getBufferSize());
    final InputStream inputStream = new ByteArrayInputStream(request(EXCESSIVE_HEADER_COUNT));

    final RequestHeaderFieldsTooLargeException ex = assertThrows(RequestHeaderFieldsTooLargeException.class,
        () -> parser.parse(inBuffer, inputStream));
    assertEquals(HEADER_COUNT_EXCEEDED, ex.getMessage());
  }

  @Test
  public void testConnectorRejectsResponseWithExcessiveHeaderCount() throws Exception {
    final HttpConnectorImpl connector = new HttpConnectorImpl();
    try (CannedResponseServer server = new CannedResponseServer(response(EXCESSIVE_HEADER_COUNT, 0))) {
      final ConnectorRequestException ex = assertThrows(ConnectorRequestException.class,
          () -> connector.createRequest().url(server.url()).get().execute());
      assertCausedByMessageConstraintViolation(ex, HEADER_COUNT_EXCEEDED);
    } finally {
      connector.getHttpClient().close();
    }
  }

  @Test
  public void testConnectorRejectsResponseWithExcessiveHeaderLineLength() throws Exception {
    final HttpConnectorImpl connector = new HttpConnectorImpl();
    try (CannedResponseServer server = new CannedResponseServer(response(0, EXCESSIVE_HEADER_VALUE_LENGTH))) {
      final ConnectorRequestException ex = assertThrows(ConnectorRequestException.class,
          () -> connector.createRequest().url(server.url()).get().execute());
      assertCausedByMessageConstraintViolation(ex, LINE_LENGTH_EXCEEDED);
    } finally {
      connector.getHttpClient().close();
    }
  }

  @Test
  public void testConnectorAcceptsResponseWithinDefaultLimits() throws Exception {
    final HttpConnectorImpl connector = new HttpConnectorImpl();
    try (CannedResponseServer server = new CannedResponseServer(response(100, 4096))) {
      final HttpResponse response = connector.createRequest().url(server.url()).get().execute();
      try {
        assertEquals(Integer.valueOf(200), response.getStatusCode());
        assertEquals("value", response.getHeader("X-Header-99"));
        assertEquals(4096, response.getHeader("X-Large").length());
        assertEquals("ok", response.getResponse());
      } finally {
        response.close();
      }
    } finally {
      connector.getHttpClient().close();
    }
  }

  private static void assertCausedByMessageConstraintViolation(final Throwable thrown, final String expectedMessage) {
    Throwable cause = thrown;
    while (cause != null && !(cause instanceof MessageConstraintException)) {
      cause = cause.getCause();
    }
    assertNotNull("expected a MessageConstraintException in the cause chain of " + thrown, cause);
    assertEquals(expectedMessage, cause.getMessage());
  }

  private static byte[] response(final int extraHeaderCount, final int largeHeaderValueLength) {
    final StringBuilder sb = new StringBuilder();
    sb.append("HTTP/1.1 200 OK\r\n");
    sb.append("Content-Type: text/plain\r\n");
    sb.append("Content-Length: 2\r\n");
    sb.append("Connection: close\r\n");
    appendHeaders(sb, extraHeaderCount, largeHeaderValueLength);
    sb.append("\r\n");
    sb.append("ok");
    return sb.toString().getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] request(final int extraHeaderCount) {
    final StringBuilder sb = new StringBuilder();
    sb.append("GET / HTTP/1.1\r\n");
    sb.append("Host: localhost\r\n");
    appendHeaders(sb, extraHeaderCount, 0);
    sb.append("\r\n");
    return sb.toString().getBytes(StandardCharsets.US_ASCII);
  }

  private static void appendHeaders(final StringBuilder sb, final int headerCount, final int largeHeaderValueLength) {
    for (int i = 0; i < headerCount; i++) {
      sb.append("X-Header-").append(i).append(": value\r\n");
    }
    if (largeHeaderValueLength > 0) {
      sb.append("X-Large: ");
      for (int i = 0; i < largeHeaderValueLength; i++) {
        sb.append('a');
      }
      sb.append("\r\n");
    }
  }

  /**
   * Minimal HTTP/1.1 server playing a malicious upstream: every connection gets the same canned
   * response once its request head has been read.
   */
  private static final class CannedResponseServer implements AutoCloseable {

    private final ServerSocket serverSocket;
    private final byte[] response;

    CannedResponseServer(final byte[] response) throws IOException {
      this.serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
      this.response = response;
      final Thread acceptor = new Thread(this::serve, "Http1ConfigDefaultsTest-server");
      acceptor.setDaemon(true);
      acceptor.start();
    }

    String url() {
      return "http://127.0.0.1:" + serverSocket.getLocalPort() + "/";
    }

    private void serve() {
      while (!serverSocket.isClosed()) {
        try (Socket socket = serverSocket.accept()) {
          socket.setSoTimeout(10000);
          readRequestHead(socket.getInputStream());
          final OutputStream outputStream = socket.getOutputStream();
          outputStream.write(response);
          outputStream.flush();
        } catch (final IOException ignore) {
          // the client aborting a rejected response, or the server being closed
        }
      }
    }

    private static void readRequestHead(final InputStream inputStream) throws IOException {
      // consume everything up to and including the empty line terminating the request head
      int matched = 0;
      final byte[] terminator = {'\r', '\n', '\r', '\n'};
      while (matched < terminator.length) {
        final int b = inputStream.read();
        if (b == -1) {
          throw new IOException("connection closed before the end of the request head");
        }
        if (b == terminator[matched]) {
          matched++;
        } else {
          matched = b == '\r' ? 1 : 0;
        }
      }
    }

    @Override
    public void close() throws IOException {
      serverSocket.close();
    }
  }

}
