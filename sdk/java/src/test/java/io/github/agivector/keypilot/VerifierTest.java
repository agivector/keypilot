/*
 * Description: Tests shared vectors and cache policy behavior of the KeyPilot Java SDK.
 * Author: vectorshi
 * Created: 2026-11-25
 */
package io.github.agivector.keypilot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Description: Verifies shared vectors and SDK cache behavior.
 * Author: vectorshi
 * Created: 2026-11-25
 * Parameters: None.
 * Returns: None.
 */
final class VerifierTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Path REPOSITORY_ROOT = Path.of("..", "..");

    /**
     * Description: Verifies all fixed RS256 and PS256 cross-language cases.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns: None.
     * Exceptions:
     *   Exception: Vector file or local server setup failure.
     */
    @Test
    void sharedSignatureVectors() throws Exception {
        byte[] jwks = readVector("keys", "rsa-public-jwks.json");
        JsonNode vectors = OBJECT_MAPPER.readTree(readVector("cases", "signatures.json"));
        try (TestJwksServer server = new TestJwksServer(jwks, "\"vectors-v1\"")) {
            Verifier verifier = newVerifier(server, FailureMode.STRICT);
            for (JsonNode testCase : vectors.get("cases")) {
                byte[] payload = decode(testCase.get("payload_base64").asText());
                String signature = testCase.get("signature_base64url").asText();
                String kid = testCase.get("kid").asText();
                CryptoAlgorithm algorithm = CryptoAlgorithm.fromCode(testCase.get("algorithm").asInt());
                if (testCase.get("expected_valid").asBoolean()) {
                    VerificationResult result = verifier.verify(payload, signature, kid, algorithm);
                    assertTrue(result.valid(), testCase.get("name").asText());
                    assertEquals(kid, result.kid());
                    assertEquals(algorithm, result.algorithm());
                } else {
                    KeyPilotException error = assertThrows(
                            KeyPilotException.class,
                            () -> verifier.verify(payload, signature, kid, algorithm),
                            testCase.get("name").asText()
                    );
                    assertEquals(testCase.get("expected_error_code").asInt(), error.getCode().getCode());
                }
            }
        }
    }

    /**
     * Description: Verifies ETag refresh, unknown-kid cooldown, replacement, and invalid refresh retention.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns: None.
     * Exceptions:
     *   Exception: Vector file or local server setup failure.
     */
    @Test
    void etagUnknownKidCooldownAndReplacement() throws Exception {
        byte[] jwks = readVector("keys", "rsa-public-jwks.json");
        try (TestJwksServer server = new TestJwksServer(jwks, "\"v1\"")) {
            Verifier verifier = newVerifier(server, FailureMode.STRICT);
            MutableClock clock = new MutableClock(Instant.parse("2026-11-25T00:00:00Z"));
            verifier.setClock(clock);
            VectorInput input = validRs256Input();

            verifier.verify(input.payload(), input.signature(), "vector-rs256-2026-01", CryptoAlgorithm.RS256);
            clock.advance(Duration.ofMinutes(2));
            verifier.verify(input.payload(), input.signature(), "vector-rs256-2026-01", CryptoAlgorithm.RS256);
            assertEquals(2, server.requestCount());
            assertEquals("\"v1\"", server.lastIfNoneMatch());

            KeyPilotException firstUnknown = assertThrows(
                    KeyPilotException.class,
                    () -> verifier.verify(input.payload(), input.signature(), "unknown-1", CryptoAlgorithm.RS256)
            );
            assertEquals(SdkErrorCode.KEY_NOT_FOUND, firstUnknown.getCode());
            int firstUnknownCount = server.requestCount();
            KeyPilotException secondUnknown = assertThrows(
                    KeyPilotException.class,
                    () -> verifier.verify(input.payload(), input.signature(), "unknown-2", CryptoAlgorithm.RS256)
            );
            assertEquals(SdkErrorCode.KEY_NOT_FOUND, secondUnknown.getCode());
            assertEquals(firstUnknownCount, server.requestCount());

            byte[] psOnly = singleJwk(jwks, "vector-ps256-2026-01");
            server.set(psOnly, "\"v2\"", 200);
            verifier.refresh();
            assertFalse(verifier.hasCachedKey("vector-rs256-2026-01"));
            assertTrue(verifier.hasCachedKey("vector-ps256-2026-01"));

            server.set(duplicateJwks(psOnly), "\"v3\"", 200);
            KeyPilotException duplicate = assertThrows(KeyPilotException.class, verifier::refresh);
            assertEquals(SdkErrorCode.JWKS_INVALID_RESPONSE, duplicate.getCode());
            assertTrue(verifier.hasCachedKey("vector-ps256-2026-01"));
        }
    }

    /**
     * Description: Verifies STRICT and AVAILABLE stale-cache behavior.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns: None.
     * Exceptions:
     *   Exception: Vector file or local server setup failure.
     */
    @Test
    void failureModes() throws Exception {
        byte[] jwks = readVector("keys", "rsa-public-jwks.json");
        VectorInput input = validRs256Input();
        for (FailureMode mode : FailureMode.values()) {
            try (TestJwksServer server = new TestJwksServer(jwks, "\"" + mode.name().toLowerCase() + "-v1\"")) {
                Verifier verifier = newVerifier(server, mode);
                MutableClock clock = new MutableClock(Instant.parse("2026-11-25T00:00:00Z"));
                verifier.setClock(clock);
                verifier.verify(input.payload(), input.signature(), "vector-rs256-2026-01", CryptoAlgorithm.RS256);
                server.set(new byte[0], "", 503);
                clock.advance(Duration.ofMinutes(2));
                if (mode == FailureMode.STRICT) {
                    KeyPilotException expired = assertThrows(
                            KeyPilotException.class,
                            () -> verifier.verify(input.payload(), input.signature(), "vector-rs256-2026-01", CryptoAlgorithm.RS256)
                    );
                    assertEquals(SdkErrorCode.CACHE_EXPIRED, expired.getCode());
                } else {
                    VerificationResult result = verifier.verify(
                            input.payload(), input.signature(), "vector-rs256-2026-01", CryptoAlgorithm.RS256
                    );
                    assertTrue(result.valid());
                    server.waitForRequests(2);
                    clock.advance(Duration.ofMinutes(2));
                    KeyPilotException expired = assertThrows(
                            KeyPilotException.class,
                            () -> verifier.verify(input.payload(), input.signature(), "vector-rs256-2026-01", CryptoAlgorithm.RS256)
                    );
                    assertEquals(SdkErrorCode.CACHE_EXPIRED, expired.getCode());
                }
            }
        }
    }

    /**
     * Description: Verifies HTTPS enforcement in configuration.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns: None.
     */
    @Test
    void configurationValidation() {
        KeyPilotException error = assertThrows(KeyPilotException.class, () -> Config.builder()
                .issuer("issuer")
                .jwksUrl("http://example.com/jwks.json")
                .allowedAlgorithms(Set.of(CryptoAlgorithm.RS256))
                .build());
        assertEquals(SdkErrorCode.CONFIGURATION_ERROR, error.getCode());
        Config configuration = Config.builder()
                .issuer("issuer")
                .jwksUrl("https://example.com/jwks.json")
                .allowedAlgorithms(Set.of(CryptoAlgorithm.RS256))
                .build();
        assertEquals(Duration.ofMinutes(1), configuration.getRefreshInterval());
    }

    /**
     * Description: Verifies removal at the 60-second STRICT refresh boundary.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns: None.
     * Exceptions:
     *   Exception: Vector file or local server setup failure.
     */
    @Test
    void rejectsRemovedCachedKeyAtStrictRefreshBoundary() throws Exception {
        byte[] jwks = readVector("keys", "rsa-public-jwks.json");
        try (TestJwksServer server = new TestJwksServer(jwks, "\"revocation-v1\"")) {
            Verifier verifier = newVerifier(server, FailureMode.STRICT);
            MutableClock clock = new MutableClock(Instant.parse("2026-11-25T00:00:00Z"));
            verifier.setClock(clock);
            VectorInput input = validRs256Input();
            verifier.verify(input.payload(), input.signature(), "vector-rs256-2026-01", CryptoAlgorithm.RS256);
            server.set(singleJwk(jwks, "vector-ps256-2026-01"), "\"revocation-v2\"", 200);
            clock.advance(Duration.ofMinutes(1));
            KeyPilotException error = assertThrows(
                    KeyPilotException.class,
                    () -> verifier.verify(
                            input.payload(), input.signature(), "vector-rs256-2026-01", CryptoAlgorithm.RS256)
            );
            assertEquals(SdkErrorCode.KEY_NOT_FOUND, error.getCode());
        }
    }

    /**
     * Description: Creates a verifier with short deterministic cache policy values.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   server: Local JWKS test server.
     *   mode: Cache failure policy.
     * Returns:
     *   Verifier: Configured verifier.
     */
    private static Verifier newVerifier(TestJwksServer server, FailureMode mode) {
        return new Verifier(Config.builder()
                .issuer("vector-issuer")
                .jwksUrl(server.url())
                .allowedAlgorithms(Set.of(CryptoAlgorithm.RS256, CryptoAlgorithm.PS256))
                .refreshInterval(Duration.ofMinutes(1))
                .requestTimeout(Duration.ofSeconds(1))
                .unknownKidCooldown(Duration.ofMinutes(1))
                .maxStale(Duration.ofMinutes(3))
                .failureMode(mode)
                .build());
    }

    /**
     * Description: Reads one shared vector file from the repository root.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   directory: Vector subdirectory.
     *   name: Vector file name.
     * Returns:
     *   byte[]: File content.
     * Exceptions:
     *   IOException: File read failure.
     */
    private static byte[] readVector(String directory, String name) throws IOException {
        return Files.readAllBytes(REPOSITORY_ROOT.resolve("test-vectors").resolve(directory).resolve(name));
    }

    /**
     * Description: Decodes one unpadded Base64URL test value.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   value: Unpadded Base64URL text.
     * Returns:
     *   byte[]: Decoded bytes.
     */
    private static byte[] decode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    /**
     * Description: Returns payload and signature from the shared valid RS256 case.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   VectorInput: Decoded payload and signature.
     * Exceptions:
     *   IOException: Vector read or parse failure.
     */
    private static VectorInput validRs256Input() throws IOException {
        JsonNode vectors = OBJECT_MAPPER.readTree(readVector("cases", "signatures.json"));
        for (JsonNode testCase : vectors.get("cases")) {
            if ("rs256_valid".equals(testCase.get("name").asText())) {
                return new VectorInput(
                        decode(testCase.get("payload_base64").asText()),
                        decode(testCase.get("signature_base64url").asText())
                );
            }
        }
        throw new IOException("valid RS256 vector is missing");
    }

    /**
     * Description: Returns a JWKS document containing only the selected key.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   content: Source JWKS bytes.
     *   kid: Key to retain.
     * Returns:
     *   byte[]: Single-key JWKS JSON.
     * Exceptions:
     *   IOException: JSON parse or serialization failure.
     */
    private static byte[] singleJwk(byte[] content, String kid) throws IOException {
        JsonNode document = OBJECT_MAPPER.readTree(content);
        ObjectNode result = OBJECT_MAPPER.createObjectNode();
        ArrayNode keys = result.putArray("keys");
        for (JsonNode key : document.get("keys")) {
            if (kid.equals(key.get("kid").asText())) {
                keys.add(key);
            }
        }
        return OBJECT_MAPPER.writeValueAsBytes(result);
    }

    /**
     * Description: Creates an invalid JWKS containing the same kid twice.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   content: Valid single-key JWKS bytes.
     * Returns:
     *   byte[]: Invalid duplicate-key JWKS JSON.
     * Exceptions:
     *   IOException: JSON parse or serialization failure.
     */
    private static byte[] duplicateJwks(byte[] content) throws IOException {
        JsonNode key = OBJECT_MAPPER.readTree(content).get("keys").get(0);
        ObjectNode result = OBJECT_MAPPER.createObjectNode();
        result.putArray("keys").add(key).add(key);
        return OBJECT_MAPPER.writeValueAsBytes(result);
    }

    /**
     * Description: Stores decoded shared vector input.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   payload: Exact payload bytes.
     *   signature: Raw signature bytes.
     * Returns: None.
     */
    private record VectorInput(byte[] payload, byte[] signature) {
    }

    /**
     * Description: Provides deterministic mutable time for cache tests.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   initial: Initial UTC instant.
     * Returns: None.
     */
    private static final class MutableClock extends Clock {
        private Instant current;

        /**
         * Description: Initializes the mutable UTC clock.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   initial: Initial UTC instant.
         * Returns: None.
         */
        private MutableClock(Instant initial) {
            current = initial;
        }

        /**
         * Description: Returns the UTC clock zone.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters: None.
         * Returns:
         *   ZoneId: UTC zone.
         */
        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        /**
         * Description: Returns this clock because tests always use UTC.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   zone: Requested zone.
         * Returns:
         *   Clock: Current mutable clock for UTC.
         * Exceptions:
         *   IllegalArgumentException: Requested zone is not UTC.
         */
        @Override
        public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new IllegalArgumentException("MutableClock only supports UTC");
            }
            return this;
        }

        /**
         * Description: Returns the current deterministic instant.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters: None.
         * Returns:
         *   Instant: Current test instant.
         */
        @Override
        public synchronized Instant instant() {
            return current;
        }

        /**
         * Description: Moves deterministic time forward.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   duration: Positive duration to add.
         * Returns: None.
         */
        private synchronized void advance(Duration duration) {
            current = current.plus(duration);
        }
    }

    /**
     * Description: Provides a mutable loopback JWKS HTTP server.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   body: Initial JWKS response bytes.
     *   etag: Initial response ETag.
     * Returns: None.
     */
    private static final class TestJwksServer implements AutoCloseable {
        private final HttpServer server;
        private byte[] body;
        private String etag;
        private int status = 200;
        private int requests;
        private String lastIfNoneMatch = "";

        /**
         * Description: Starts a loopback JWKS server.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   body: Initial JWKS response bytes.
         *   etag: Initial response ETag.
         * Returns: None.
         * Exceptions:
         *   IOException: Server creation failure.
         */
        private TestJwksServer(byte[] body, String etag) throws IOException {
            this.body = body;
            this.etag = etag;
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/jwks.json", this::handle);
            server.start();
        }

        /**
         * Description: Returns the loopback JWKS URL.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters: None.
         * Returns:
         *   String: Local JWKS URL.
         */
        private String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks.json";
        }

        /**
         * Description: Replaces synchronized JWKS response state.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   value: JWKS response bytes.
         *   responseEtag: Response ETag.
         *   responseStatus: HTTP status code.
         * Returns: None.
         */
        private synchronized void set(byte[] value, String responseEtag, int responseStatus) {
            body = value;
            etag = responseEtag;
            status = responseStatus;
        }

        /**
         * Description: Returns the synchronized request count.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters: None.
         * Returns:
         *   int: Total request count.
         */
        private synchronized int requestCount() {
            return requests;
        }

        /**
         * Description: Returns the most recent If-None-Match value.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters: None.
         * Returns:
         *   String: Most recent header value.
         */
        private synchronized String lastIfNoneMatch() {
            return lastIfNoneMatch;
        }

        /**
         * Description: Waits for an asynchronous request count.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   expected: Minimum request count.
         * Returns: None.
         * Exceptions:
         *   InterruptedException: Test thread interrupted.
         */
        private void waitForRequests(int expected) throws InterruptedException {
            long deadline = System.nanoTime() + Duration.ofSeconds(1).toNanos();
            while (System.nanoTime() < deadline) {
                if (requestCount() >= expected) {
                    return;
                }
                Thread.sleep(5);
            }
            throw new AssertionError("expected at least " + expected + " requests, got " + requestCount());
        }

        /**
         * Description: Handles one synchronized JWKS request.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   exchange: Incoming HTTP exchange.
         * Returns: None.
         * Exceptions:
         *   IOException: Response write failure.
         */
        private void handle(HttpExchange exchange) throws IOException {
            byte[] responseBody;
            String responseEtag;
            int responseStatus;
            synchronized (this) {
                requests++;
                lastIfNoneMatch = exchange.getRequestHeaders().getFirst("If-None-Match");
                responseBody = body;
                responseEtag = etag;
                responseStatus = status;
                if (responseStatus == 200 && !responseEtag.isEmpty() && responseEtag.equals(lastIfNoneMatch)) {
                    responseStatus = 304;
                }
            }
            if (!responseEtag.isEmpty()) {
                exchange.getResponseHeaders().set("ETag", responseEtag);
            }
            if (responseStatus == 304) {
                exchange.sendResponseHeaders(responseStatus, -1);
            } else {
                exchange.sendResponseHeaders(responseStatus, responseBody.length);
                exchange.getResponseBody().write(responseBody);
            }
            exchange.close();
        }

        /**
         * Description: Stops the loopback JWKS server.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters: None.
         * Returns: None.
         */
        @Override
        public void close() {
            server.stop(0);
        }
    }
}
