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
package org.apache.hc.client5.http.ssl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.URIScheme;
import org.apache.hc.core5.net.NamedEndpoint;
import org.apache.hc.core5.reactor.ssl.SSLBufferMode;
import org.apache.hc.core5.reactor.ssl.SSLSessionInitializer;
import org.apache.hc.core5.reactor.ssl.SSLSessionVerifier;
import org.apache.hc.core5.reactor.ssl.TlsDetails;
import org.apache.hc.core5.reactor.ssl.TransportSecurityLayer;
import org.apache.hc.core5.util.Timeout;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Regression tests for CVE-2026-71290 (GHSA-72q8-9rgw-5g6j) in the shaded httpclient5
 * {@link AbstractClientTlsStrategy}: when the hostname verification policy is
 * {@link HostnameVerificationPolicy#BUILTIN} or {@link HostnameVerificationPolicy#BOTH}, the
 * async TLS upgrade must hand the HTTPS endpoint identification algorithm to the
 * {@link SSLEngine}. Otherwise the JSSE built-in hostname check is silently skipped and a
 * certificate that is trusted but issued for a different host is accepted (man-in-the-middle).
 *
 * @see <a href="https://github.com/advisories/GHSA-72q8-9rgw-5g6j">GHSA-72q8-9rgw-5g6j</a>
 */
public class AbstractClientTlsStrategyHostnameVerificationTest {

  private static final String VICTIM_HOST = "victim.example";
  private static final String ATTACKER_HOST = "attacker.example";
  private static final int PORT = 443;
  private static final char[] PASSWORD = "changeit".toCharArray();

  /** Client context that trusts the attacker's certificate (a valid chain, but for the wrong host). */
  private static SSLContext clientContext;
  /** Server context presenting a certificate issued only for {@link #ATTACKER_HOST}. */
  private static SSLContext attackerServerContext;

  @BeforeClass
  public static void createContexts() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair keyPair = generator.generateKeyPair();
    X509Certificate attackerCertificate = selfSignedCertificate(ATTACKER_HOST, keyPair);

    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setKeyEntry("attacker", keyPair.getPrivate(), PASSWORD, new Certificate[] {attackerCertificate});
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, PASSWORD);
    attackerServerContext = SSLContext.getInstance("TLS");
    attackerServerContext.init(keyManagerFactory.getKeyManagers(), null, null);

    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("attacker", attackerCertificate);
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);
    clientContext = SSLContext.getInstance("TLS");
    clientContext.init(null, trustManagerFactory.getTrustManagers(), null);
  }

  @Test
  public void builtinPolicyAppliesEndpointIdentificationToEngine() {
    SSLEngine engine = initializeClientEngine(HostnameVerificationPolicy.BUILTIN, VICTIM_HOST).engine;

    assertEquals(URIScheme.HTTPS.id, engine.getSSLParameters().getEndpointIdentificationAlgorithm());
  }

  @Test
  public void bothPolicyAppliesEndpointIdentificationToEngine() {
    SSLEngine engine = initializeClientEngine(HostnameVerificationPolicy.BOTH, VICTIM_HOST).engine;

    assertEquals(URIScheme.HTTPS.id, engine.getSSLParameters().getEndpointIdentificationAlgorithm());
  }

  @Test
  public void clientPolicyLeavesEndpointIdentificationToHostnameVerifier() {
    SSLEngine engine = initializeClientEngine(HostnameVerificationPolicy.CLIENT, VICTIM_HOST).engine;

    assertNull(engine.getSSLParameters().getEndpointIdentificationAlgorithm());
  }

  @Test
  public void builtinPolicyRejectsTrustedCertificateIssuedForAnotherHost() {
    // the client connects to victim.example; a man-in-the-middle answers with a certificate
    // that is trusted but issued for attacker.example
    ClientSession client = initializeClientEngine(HostnameVerificationPolicy.BUILTIN, VICTIM_HOST);
    SSLEngine server = attackerServerContext.createSSLEngine();
    server.setUseClientMode(false);

    SSLException exception = assertThrows(SSLException.class, () -> {
      handshake(client.engine, server);
      client.layer.verifier.verify(client.endpoint, client.engine);
    });

    assertTrue("handshake must fail on the server identity check, but failed with: " + exception,
        hasCause(exception, CertificateException.class));
  }

  @Test
  public void builtinPolicyAcceptsCertificateIssuedForTheTargetHost() throws Exception {
    // control: the same setup succeeds when the certificate matches the requested host
    ClientSession client = initializeClientEngine(HostnameVerificationPolicy.BUILTIN, ATTACKER_HOST);
    SSLEngine server = attackerServerContext.createSSLEngine();
    server.setUseClientMode(false);

    handshake(client.engine, server);
    client.layer.verifier.verify(client.endpoint, client.engine);

    assertNotNull(client.engine.getSession().getPeerCertificates());
  }

  /**
   * Runs the real {@link AbstractClientTlsStrategy#upgrade(TransportSecurityLayer, NamedEndpoint,
   * Object, Timeout, org.apache.hc.core5.concurrent.FutureCallback)} and applies the session
   * initializer it registers to a fresh client {@link SSLEngine}, as the I/O reactor would.
   */
  private static ClientSession initializeClientEngine(HostnameVerificationPolicy policy, String host) {
    DefaultClientTlsStrategy strategy = new DefaultClientTlsStrategy(clientContext, policy, null);
    RecordingTransportSecurityLayer layer = new RecordingTransportSecurityLayer();
    HttpHost endpoint = new HttpHost(URIScheme.HTTPS.id, host, PORT);

    strategy.upgrade(layer, endpoint, null, Timeout.ofSeconds(5), null);

    assertNotNull("upgrade must start TLS with a session initializer", layer.initializer);
    SSLEngine engine = layer.sslContext.createSSLEngine(host, PORT);
    engine.setUseClientMode(true);
    layer.initializer.initialize(endpoint, engine);
    return new ClientSession(layer, endpoint, engine);
  }

  /** Drives an in-memory TLS handshake between the two engines. */
  private static void handshake(SSLEngine client, SSLEngine server) throws SSLException {
    ByteBuffer empty = ByteBuffer.allocate(0);
    ByteBuffer clientToServer = ByteBuffer.allocate(64 * 1024);
    ByteBuffer serverToClient = ByteBuffer.allocate(64 * 1024);
    ByteBuffer clientApplicationData = ByteBuffer.allocate(64 * 1024);
    ByteBuffer serverApplicationData = ByteBuffer.allocate(64 * 1024);

    client.beginHandshake();
    server.beginHandshake();
    for (int i = 0; i < 100; i++) {
      client.wrap(empty, clientToServer);
      runDelegatedTasks(client);
      server.wrap(empty, serverToClient);
      runDelegatedTasks(server);

      clientToServer.flip();
      serverToClient.flip();
      client.unwrap(serverToClient, clientApplicationData);
      runDelegatedTasks(client);
      server.unwrap(clientToServer, serverApplicationData);
      runDelegatedTasks(server);
      clientToServer.compact();
      serverToClient.compact();

      if (client.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING
          && server.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING) {
        return;
      }
    }
    throw new AssertionError("TLS handshake did not complete");
  }

  private static void runDelegatedTasks(SSLEngine engine) {
    Runnable task;
    while ((task = engine.getDelegatedTask()) != null) {
      task.run();
    }
  }

  private static boolean hasCause(Throwable throwable, Class<? extends Throwable> type) {
    for (Throwable current = throwable; current != null; current = current.getCause()) {
      if (type.isInstance(current)) {
        return true;
      }
    }
    return false;
  }

  /** Builds a DER encoded, self-signed ECDSA certificate whose only DNS name is {@code dnsName}. */
  private static X509Certificate selfSignedCertificate(String dnsName, KeyPair keyPair) throws Exception {
    byte[] hostName = dnsName.getBytes(StandardCharsets.US_ASCII);
    byte[] ecdsaWithSha256 = der(0x30, der(0x06, bytes(0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02)));
    byte[] name = der(0x30, der(0x31, der(0x30, der(0x06, bytes(0x55, 0x04, 0x03)), der(0x0C, hostName))));
    byte[] validity = der(0x30,
        der(0x17, "200101000000Z".getBytes(StandardCharsets.US_ASCII)),
        der(0x17, "491231235959Z".getBytes(StandardCharsets.US_ASCII)));
    byte[] subjectAltName = der(0x30, der(0x30,
        der(0x06, bytes(0x55, 0x1D, 0x11)),
        der(0x04, der(0x30, der(0x82, hostName)))));
    byte[] tbsCertificate = der(0x30,
        der(0xA0, der(0x02, bytes(0x02))),
        der(0x02, bytes(0x01)),
        ecdsaWithSha256,
        name,
        validity,
        name,
        keyPair.getPublic().getEncoded(),
        der(0xA3, subjectAltName));

    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(keyPair.getPrivate());
    signer.update(tbsCertificate);
    byte[] signature = signer.sign();
    byte[] signatureBits = new byte[signature.length + 1];
    System.arraycopy(signature, 0, signatureBits, 1, signature.length);

    byte[] certificate = der(0x30, tbsCertificate, ecdsaWithSha256, der(0x03, signatureBits));
    return (X509Certificate) CertificateFactory.getInstance("X.509")
        .generateCertificate(new ByteArrayInputStream(certificate));
  }

  private static byte[] der(int tag, byte[]... contents) {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    for (byte[] content : contents) {
      body.write(content, 0, content.length);
    }
    int length = body.size();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(tag);
    if (length < 0x80) {
      out.write(length);
    } else if (length < 0x100) {
      out.write(0x81);
      out.write(length);
    } else {
      out.write(0x82);
      out.write(length >> 8);
      out.write(length & 0xFF);
    }
    out.write(body.toByteArray(), 0, length);
    return out.toByteArray();
  }

  private static byte[] bytes(int... values) {
    byte[] result = new byte[values.length];
    for (int i = 0; i < values.length; i++) {
      result[i] = (byte) values[i];
    }
    return result;
  }

  private static final class ClientSession {

    private final RecordingTransportSecurityLayer layer;
    private final NamedEndpoint endpoint;
    private final SSLEngine engine;

    private ClientSession(RecordingTransportSecurityLayer layer, NamedEndpoint endpoint, SSLEngine engine) {
      this.layer = layer;
      this.endpoint = endpoint;
      this.engine = engine;
    }
  }

  /** Captures the TLS start request instead of performing network I/O. */
  private static final class RecordingTransportSecurityLayer implements TransportSecurityLayer {

    private SSLContext sslContext;
    private SSLSessionInitializer initializer;
    private SSLSessionVerifier verifier;

    @Override
    public void startTls(
        SSLContext sslContext,
        NamedEndpoint endpoint,
        SSLBufferMode sslBufferMode,
        SSLSessionInitializer initializer,
        SSLSessionVerifier verifier,
        Timeout handshakeTimeout) {
      this.sslContext = sslContext;
      this.initializer = initializer;
      this.verifier = verifier;
    }

    @Override
    public TlsDetails getTlsDetails() {
      return null;
    }
  }
}
