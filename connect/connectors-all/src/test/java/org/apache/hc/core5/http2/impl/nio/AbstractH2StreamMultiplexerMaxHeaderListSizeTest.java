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
package org.apache.hc.core5.http2.impl.nio;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.RequestHeaderFieldsTooLargeException;
import org.apache.hc.core5.http.config.CharCodingConfig;
import org.apache.hc.core5.http.impl.BasicHttpConnectionMetrics;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.nio.AsyncPushConsumer;
import org.apache.hc.core5.http.nio.AsyncServerExchangeHandler;
import org.apache.hc.core5.http.nio.HandlerFactory;
import org.apache.hc.core5.http.nio.command.ExecutableCommand;
import org.apache.hc.core5.http.protocol.HttpProcessor;
import org.apache.hc.core5.http2.H2ConnectionException;
import org.apache.hc.core5.http2.config.H2Config;
import org.apache.hc.core5.http2.frame.DefaultFrameFactory;
import org.apache.hc.core5.http2.frame.FrameFactory;
import org.apache.hc.core5.http2.frame.RawFrame;
import org.apache.hc.core5.http2.frame.StreamIdGenerator;
import org.apache.hc.core5.http2.hpack.HPackDecoder;
import org.apache.hc.core5.http2.hpack.HPackEncoder;
import org.apache.hc.core5.http2.hpack.HeaderListConstraintException;
import org.apache.hc.core5.reactor.ProtocolIOSession;
import org.apache.hc.core5.util.ByteArrayBuffer;
import org.junit.Test;

/**
 * Regression tests for CVE-2026-54428 (GHSA-v3jc-474w-2wm6) in the shaded httpcore5-h2
 * {@link AbstractH2StreamMultiplexer}: the HPACK decoder must enforce the locally configured
 * {@code MAX_HEADER_LIST_SIZE} as soon as the multiplexer is created, not only once the peer
 * has acknowledged the local SETTINGS frame. Otherwise a peer can send oversized header blocks
 * during that window and exhaust memory.
 *
 * @see <a href="https://github.com/advisories/GHSA-v3jc-474w-2wm6">GHSA-v3jc-474w-2wm6</a>
 */
public class AbstractH2StreamMultiplexerMaxHeaderListSizeTest {

  private static final int MAX_HEADER_LIST_SIZE = 128;

  private static final FrameFactory FRAME_FACTORY = DefaultFrameFactory.INSTANCE;

  @Test
  public void testHPackDecoderUsesConfiguredMaxHeaderListSizeImmediately() throws Exception {
    final ServerH2StreamMultiplexer multiplexer = new ServerH2StreamMultiplexer(
        fakeIOSession(),
        fakeHttpProcessor(),
        fakeServerHandlerFactory(),
        CharCodingConfig.DEFAULT,
        smallHeaderListConfig());

    assertEquals(MAX_HEADER_LIST_SIZE, getHPackDecoder(multiplexer).getMaxListSize());
  }

  @Test
  public void testHPackDecoderUsesDefaultMaxHeaderListSizeImmediately() throws Exception {
    final ClientH2StreamMultiplexer multiplexer = new ClientH2StreamMultiplexer(
        fakeIOSession(),
        fakeHttpProcessor(),
        null,
        CharCodingConfig.DEFAULT);

    final int maxListSize = getHPackDecoder(multiplexer).getMaxListSize();
    assertEquals(H2Config.DEFAULT.getMaxHeaderListSize(), maxListSize);
    assertTrue("header list size must not be unlimited before SETTINGS ACK",
        maxListSize < Integer.MAX_VALUE);
  }

  @Test
  public void testOversizedHeaderBlockRejectedBeforeSettingsAckServerSide() throws Exception {
    // Freshly constructed multiplexer: no onConnect(), no SETTINGS ACK from the peer,
    // which is exactly the window an attacker uses to submit a header bomb.
    final ServerH2StreamMultiplexer multiplexer = new ServerH2StreamMultiplexer(
        fakeIOSession(),
        fakeHttpProcessor(),
        fakeServerHandlerFactory(),
        CharCodingConfig.DEFAULT,
        smallHeaderListConfig());

    final ByteBuffer headerBlock = encodeOversizedHeaderBlock();
    assertTrue(headerBlock.remaining() > 0);

    assertThrows(RequestHeaderFieldsTooLargeException.class, () -> multiplexer.decodeHeaders(headerBlock));
  }

  @Test
  public void testOversizedHeaderBlockRejectedBeforeSettingsAckClientSide() throws Exception {
    // A malicious server answering before it has acknowledged the client's SETTINGS
    final ClientH2StreamMultiplexer multiplexer = new ClientH2StreamMultiplexer(
        fakeIOSession(),
        fakeHttpProcessor(),
        smallHeaderListConfig(),
        CharCodingConfig.DEFAULT);

    final ByteBuffer headerBlock = encodeOversizedHeaderBlock();

    assertThrows(HeaderListConstraintException.class, () -> multiplexer.decodeHeaders(headerBlock));
  }

  @Test
  public void testOversizedHeaderFrameRejectedBeforeSettingsAck() throws Exception {
    final RecordingStreamHandler streamHandler = new RecordingStreamHandler();
    final AbstractH2StreamMultiplexer multiplexer = new H2StreamMultiplexerImpl(streamHandler);

    // HEADERS frame with END_HEADERS sent by the peer straight away, i.e. before
    // our local SETTINGS (MAX_HEADER_LIST_SIZE) have been acknowledged.
    final RawFrame headerFrame = FRAME_FACTORY.createHeaders(2, encodeOversizedHeaderBlock(), true, false);
    multiplexer.onInput(ByteBuffer.wrap(toBytes(headerFrame)));

    assertTrue(streamHandler.handledException instanceof HeaderListConstraintException);
    assertNull(streamHandler.consumedHeaders);
  }

  @Test
  public void testOversizedContinuationFramesRejectedBeforeSettingsAck() throws Exception {
    final RecordingStreamHandler streamHandler = new RecordingStreamHandler();
    final AbstractH2StreamMultiplexer multiplexer = new H2StreamMultiplexerImpl(streamHandler);

    // Same header bomb, split over a HEADERS frame and a CONTINUATION frame
    final ByteBuffer headerBlock = encodeOversizedHeaderBlock();
    final int split = headerBlock.remaining() / 2;
    final ByteBuffer first = ByteBuffer.wrap(headerBlock.array(), headerBlock.position(), split);
    final ByteBuffer second = ByteBuffer.wrap(
        headerBlock.array(), headerBlock.position() + split, headerBlock.remaining() - split);
    final RawFrame headerFrame = FRAME_FACTORY.createHeaders(2, first, false, false);
    final RawFrame continuationFrame = FRAME_FACTORY.createContinuation(2, second, true);
    final ByteBuffer input = ByteBuffer.wrap(toBytes(headerFrame, continuationFrame));

    assertThrows(HeaderListConstraintException.class, () -> multiplexer.onInput(input));
    assertNull(streamHandler.consumedHeaders);
  }

  @Test
  public void testHeaderFrameWithinLimitAcceptedBeforeSettingsAck() throws Exception {
    final RecordingStreamHandler streamHandler = new RecordingStreamHandler();
    final AbstractH2StreamMultiplexer multiplexer = new H2StreamMultiplexerImpl(streamHandler);

    final List<Header> headers = new ArrayList<>();
    headers.add(new BasicHeader(":status", "200"));
    headers.add(new BasicHeader("x-small", "value"));
    final RawFrame headerFrame = FRAME_FACTORY.createHeaders(2, encodeHeaderBlock(headers), true, false);
    multiplexer.onInput(ByteBuffer.wrap(toBytes(headerFrame)));

    assertNull(streamHandler.handledException);
    assertEquals(2, streamHandler.consumedHeaders.size());
    assertEquals("x-small", streamHandler.consumedHeaders.get(1).getName());
  }

  private static H2Config smallHeaderListConfig() {
    return H2Config.custom()
        .setMaxHeaderListSize(MAX_HEADER_LIST_SIZE)
        .build();
  }

  /**
   * An HPACK block that expands into a header list well beyond the 128 byte
   * {@code MAX_HEADER_LIST_SIZE} configured by the tests above.
   */
  private static ByteBuffer encodeOversizedHeaderBlock() throws Exception {
    final char[] padding = new char[256];
    for (int i = 0; i < padding.length; i++) {
      padding[i] = 'a';
    }
    final String value = new String(padding);
    final List<Header> headers = new ArrayList<>();
    for (int i = 0; i < 32; i++) {
      headers.add(new BasicHeader("x-pad-" + i, value));
    }
    return encodeHeaderBlock(headers);
  }

  private static ByteBuffer encodeHeaderBlock(final List<Header> headers) throws Exception {
    final HPackEncoder encoder = new HPackEncoder(H2Config.INIT.getHeaderTableSize(), StandardCharsets.US_ASCII);
    final ByteArrayBuffer buf = new ByteArrayBuffer(1024);
    encoder.encodeHeaders(buf, headers, true);
    return ByteBuffer.wrap(buf.array(), 0, buf.length());
  }

  private static byte[] toBytes(final RawFrame... frames) throws IOException {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final FrameOutputBuffer outBuffer = new FrameOutputBuffer(16 * 1024);
    for (final RawFrame frame : frames) {
      outBuffer.write(frame, Channels.newChannel(out));
    }
    return out.toByteArray();
  }

  private static HPackDecoder getHPackDecoder(final AbstractH2StreamMultiplexer multiplexer) throws Exception {
    final Field field = AbstractH2StreamMultiplexer.class.getDeclaredField("hPackDecoder");
    field.setAccessible(true);
    return (HPackDecoder) field.get(multiplexer);
  }

  private static ProtocolIOSession fakeIOSession() {
    final ReentrantLock lock = new ReentrantLock();
    return (ProtocolIOSession) Proxy.newProxyInstance(
        ProtocolIOSession.class.getClassLoader(),
        new Class<?>[] { ProtocolIOSession.class },
        (proxy, method, args) -> {
          switch (method.getName()) {
            case "getLock":
              return lock;
            case "getId":
            case "toString":
              return "test-session";
            case "hashCode":
              return System.identityHashCode(proxy);
            case "equals":
              return proxy == args[0];
            default:
              return defaultValue(method.getReturnType());
          }
        });
  }

  private static HttpProcessor fakeHttpProcessor() {
    return fake(HttpProcessor.class);
  }

  @SuppressWarnings("unchecked")
  private static HandlerFactory<AsyncServerExchangeHandler> fakeServerHandlerFactory() {
    return fake(HandlerFactory.class);
  }

  private static <T> T fake(final Class<T> type) {
    return type.cast(Proxy.newProxyInstance(
        type.getClassLoader(),
        new Class<?>[] { type },
        (proxy, method, args) -> {
          switch (method.getName()) {
            case "toString":
              return "fake " + type.getSimpleName();
            case "hashCode":
              return System.identityHashCode(proxy);
            case "equals":
              return proxy == args[0];
            default:
              return defaultValue(method.getReturnType());
          }
        }));
  }

  private static Object defaultValue(final Class<?> type) {
    if (type == boolean.class) {
      return Boolean.FALSE;
    } else if (type == int.class) {
      return 0;
    } else if (type == long.class) {
      return 0L;
    }
    return null;
  }

  /**
   * Multiplexer that hands every remotely initiated stream to the given handler.
   */
  static class H2StreamMultiplexerImpl extends AbstractH2StreamMultiplexer {

    private final H2StreamHandler streamHandler;

    H2StreamMultiplexerImpl(final H2StreamHandler streamHandler) {
      super(fakeIOSession(), FRAME_FACTORY, StreamIdGenerator.ODD, fakeHttpProcessor(),
          CharCodingConfig.DEFAULT, smallHeaderListConfig(), null);
      this.streamHandler = streamHandler;
    }

    @Override
    void acceptHeaderFrame() throws H2ConnectionException {
    }

    @Override
    void acceptPushRequest() throws H2ConnectionException {
    }

    @Override
    void acceptPushFrame() throws H2ConnectionException {
    }

    @Override
    H2StreamHandler createRemotelyInitiatedStream(
        final H2StreamChannel channel,
        final HttpProcessor httpProcessor,
        final BasicHttpConnectionMetrics connMetrics,
        final HandlerFactory<AsyncPushConsumer> pushHandlerFactory) throws IOException {
      return streamHandler;
    }

    @Override
    H2StreamHandler createLocallyInitiatedStream(
        final ExecutableCommand command,
        final H2StreamChannel channel,
        final HttpProcessor httpProcessor,
        final BasicHttpConnectionMetrics connMetrics) throws IOException {
      return null;
    }
  }

  /**
   * Stream handler recording the decoded headers and the exceptions it is asked to handle.
   */
  static class RecordingStreamHandler implements H2StreamHandler {

    List<Header> consumedHeaders;
    HttpException handledException;

    @Override
    public boolean isOutputReady() {
      return false;
    }

    @Override
    public void produceOutput() {
    }

    @Override
    public void consumePromise(final List<Header> headers) {
    }

    @Override
    public void consumeHeader(final List<Header> headers, final boolean endStream) {
      consumedHeaders = headers;
    }

    @Override
    public void updateInputCapacity() {
    }

    @Override
    public void consumeData(final ByteBuffer src, final boolean endStream) {
    }

    @Override
    public HandlerFactory<AsyncPushConsumer> getPushHandlerFactory() {
      return null;
    }

    @Override
    public void failed(final Exception cause) {
    }

    @Override
    public void handle(final HttpException ex, final boolean endStream) {
      handledException = ex;
    }

    @Override
    public void releaseResources() {
    }
  }

}
