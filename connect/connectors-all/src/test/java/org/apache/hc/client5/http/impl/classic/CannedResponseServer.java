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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Minimal HTTP/1.1 server playing the remote upstream: every connection gets the same canned
 * response once its request head has been read, then the connection is closed.
 */
final class CannedResponseServer implements AutoCloseable {

  private final ServerSocket serverSocket;
  private final byte[] response;

  CannedResponseServer(final String response) throws IOException {
    this.serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
    this.response = response.getBytes(StandardCharsets.US_ASCII);
    final Thread acceptor = new Thread(this::serve, "CannedResponseServer");
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
        // the client aborting the exchange, or the server being closed
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
