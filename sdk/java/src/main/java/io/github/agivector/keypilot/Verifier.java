/*
 * Description: Provides cached RS256 and PS256 verification for one trusted issuer.
 * Author: vectorshi
 * Created: 2026-11-25
 */
package io.github.agivector.keypilot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.math.BigInteger;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * Description: Manages one issuer-scoped JWKS cache and verifies signatures locally.
 * Author: vectorshi
 * Created: 2026-11-25
 * Parameters:
 *   config: Validated trusted issuer and cache configuration.
 * Returns: None.
 */
public final class Verifier {
    private static final int MAX_JWKS_RESPONSE_BYTES = 1024 * 1024;
    private static final Set<String> PRIVATE_JWK_FIELDS = Set.of("d", "p", "q", "dp", "dq", "qi", "oth");

    private final Config config;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Object cacheMonitor = new Object();
    private final Object refreshMonitor = new Object();
    private final Object unknownMonitor = new Object();

    private Map<String, CachedKey> keys = Map.of();
    private String etag = "";
    private Instant refreshTime;
    private boolean refreshing;
    private KeyPilotException refreshError;
    private Instant lastUnknownRefresh;
    private Clock clock = Clock.systemUTC();

    /**
     * Description: Initializes an empty verifier with lazy first refresh.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   config: Validated trusted issuer and cache configuration.
     * Returns: None.
     * Exceptions:
     *   KeyPilotException: CONFIGURATION_ERROR when config is null.
     */
    public Verifier(Config config) {
        if (config == null) {
            throw new KeyPilotException(SdkErrorCode.CONFIGURATION_ERROR, "config is required");
        }
        this.config = config;
    }

    /**
     * Description: Verifies exact payload bytes with a raw RSA signature.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   payload: Exact original business payload bytes.
     *   signature: Raw RSA signature bytes.
     *   kid: Trusted issuer key identifier.
     *   algorithm: Declared numeric signature algorithm.
     * Returns:
     *   VerificationResult: Successful details with valid=true.
     * Exceptions:
     *   KeyPilotException: Stable SDK error for input, refresh, key, or signature failure.
     */
    public VerificationResult verify(byte[] payload, byte[] signature, String kid, CryptoAlgorithm algorithm) {
        if (payload == null || payload.length == 0 || signature == null || signature.length == 0 || kid == null || kid.isBlank()) {
            throw new KeyPilotException(SdkErrorCode.INVALID_ARGUMENT, "payload, signature, and kid are required");
        }
        if (algorithm == null || !config.getAllowedAlgorithms().contains(algorithm)) {
            throw new KeyPilotException(SdkErrorCode.ALGORITHM_NOT_ALLOWED, "algorithm is not allowed");
        }
        boolean refreshed = ensureUsableCache();
        CachedKey cachedKey = getKey(kid);
        if (cachedKey == null && !refreshed) {
            refreshForUnknownKey();
            cachedKey = getKey(kid);
        }
        if (cachedKey == null) {
            throw new KeyPilotException(SdkErrorCode.KEY_NOT_FOUND, "kid was not found in the trusted JWKS");
        }
        if (cachedKey.algorithm() != algorithm) {
            throw new KeyPilotException(SdkErrorCode.KEY_INVALID, "JWK algorithm does not match requested algorithm");
        }
        verifyRsa(payload, signature, cachedKey.publicKey(), algorithm);
        return new VerificationResult(true, config.getIssuer(), kid, algorithm);
    }

    /**
     * Description: Verifies exact payload bytes with an unpadded Base64URL signature.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   payload: Exact original business payload bytes.
     *   signature: Unpadded Base64URL RSA signature.
     *   kid: Trusted issuer key identifier.
     *   algorithm: Declared numeric signature algorithm.
     * Returns:
     *   VerificationResult: Successful details with valid=true.
     * Exceptions:
     *   KeyPilotException: INVALID_ARGUMENT for bad encoding or another stable SDK error.
     */
    public VerificationResult verify(byte[] payload, String signature, String kid, CryptoAlgorithm algorithm) {
        if (signature == null || signature.isBlank()) {
            throw new KeyPilotException(SdkErrorCode.INVALID_ARGUMENT, "signature is required");
        }
        try {
            return verify(payload, Base64.getUrlDecoder().decode(signature), kid, algorithm);
        } catch (IllegalArgumentException error) {
            throw new KeyPilotException(SdkErrorCode.INVALID_ARGUMENT, "signature is not valid Base64URL", error);
        }
    }

    /**
     * Description: Applies STRICT or AVAILABLE refresh policy before key lookup.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   boolean: True when this call completed a synchronous refresh.
     * Exceptions:
     *   KeyPilotException: Initial refresh error or CACHE_EXPIRED for stale-cache failure.
     */
    private boolean ensureUsableCache() {
        Instant lastRefresh;
        synchronized (cacheMonitor) {
            lastRefresh = refreshTime;
        }
        if (lastRefresh == null) {
            refresh();
            return true;
        }
        Duration age = Duration.between(lastRefresh, clock.instant());
        if (age.compareTo(config.getRefreshInterval()) < 0) {
            return false;
        }
        if (config.getFailureMode() == FailureMode.STRICT || age.compareTo(config.getMaxStale()) > 0) {
            try {
                refresh();
            } catch (KeyPilotException error) {
                throw new KeyPilotException(
                        SdkErrorCode.CACHE_EXPIRED,
                        "cached JWKS is outside the allowed refresh window",
                        error
                );
            }
            return true;
        }
        startAsyncRefresh();
        return false;
    }

    /**
     * Description: Starts one asynchronous refresh for AVAILABLE mode.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns: None.
     */
    private void startAsyncRefresh() {
        synchronized (refreshMonitor) {
            if (refreshing) {
                return;
            }
            refreshing = true;
        }
        CompletableFuture.runAsync(() -> {
            try {
                executeRefreshOwner();
            } catch (KeyPilotException ignored) {
                // The last complete valid cache remains available within max_stale.
            }
        });
    }

    /**
     * Description: Performs at most one immediate unknown-kid refresh per cooldown window.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns: None.
     * Exceptions:
     *   KeyPilotException: JWKS refresh failure.
     */
    private void refreshForUnknownKey() {
        Instant now = clock.instant();
        synchronized (unknownMonitor) {
            if (lastUnknownRefresh != null
                    && Duration.between(lastUnknownRefresh, now).compareTo(config.getUnknownKidCooldown()) < 0) {
                return;
            }
            lastUnknownRefresh = now;
        }
        refresh();
    }

    /**
     * Description: Coalesces concurrent requests and atomically applies a valid JWKS snapshot.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns: None.
     * Exceptions:
     *   KeyPilotException: JWKS_UNAVAILABLE or JWKS_INVALID_RESPONSE.
     */
    void refresh() {
        synchronized (refreshMonitor) {
            if (refreshing) {
                while (refreshing) {
                    try {
                        refreshMonitor.wait();
                    } catch (InterruptedException error) {
                        Thread.currentThread().interrupt();
                        throw new KeyPilotException(SdkErrorCode.JWKS_UNAVAILABLE, "waiting for JWKS refresh was interrupted", error);
                    }
                }
                if (refreshError != null) {
                    throw refreshError;
                }
                return;
            }
            refreshing = true;
        }
        executeRefreshOwner();
    }

    /**
     * Description: Executes a refresh after the caller reserves refresh ownership.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns: None.
     * Exceptions:
     *   KeyPilotException: JWKS_UNAVAILABLE or JWKS_INVALID_RESPONSE.
     */
    private void executeRefreshOwner() {
        KeyPilotException error = null;
        try {
            String currentEtag;
            boolean initialized;
            synchronized (cacheMonitor) {
                currentEtag = etag;
                initialized = refreshTime != null;
            }
            FetchResult result = fetchJwks(currentEtag);
            synchronized (cacheMonitor) {
                if (result.notModified()) {
                    if (!initialized) {
                        throw new KeyPilotException(SdkErrorCode.JWKS_INVALID_RESPONSE, "received 304 before a valid JWKS was cached");
                    }
                    refreshTime = clock.instant();
                } else {
                    keys = Map.copyOf(result.keys());
                    etag = result.etag();
                    refreshTime = clock.instant();
                }
            }
        } catch (KeyPilotException caught) {
            error = caught;
        } finally {
            synchronized (refreshMonitor) {
                refreshError = error;
                refreshing = false;
                refreshMonitor.notifyAll();
            }
        }
        if (error != null) {
            throw error;
        }
    }

    /**
     * Description: Retrieves one complete JWKS response with ETag support.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   currentEtag: Optional ETag from the current cache.
     * Returns:
     *   FetchResult: Validated keys, response ETag, and 304 flag.
     * Exceptions:
     *   KeyPilotException: JWKS_UNAVAILABLE or JWKS_INVALID_RESPONSE.
     */
    private FetchResult fetchJwks(String currentEtag) {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(config.getJwksUrl())
                .timeout(config.getRequestTimeout())
                .GET();
        if (!currentEtag.isEmpty()) {
            requestBuilder.header("If-None-Match", currentEtag);
        }
        HttpResponse<byte[]> response;
        try {
            response = config.getHttpClient().send(requestBuilder.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException error) {
            throw new KeyPilotException(SdkErrorCode.JWKS_UNAVAILABLE, "request JWKS failed", error);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new KeyPilotException(SdkErrorCode.JWKS_UNAVAILABLE, "request JWKS was interrupted", error);
        }
        if (response.statusCode() == 304) {
            return new FetchResult(Map.of(), currentEtag, true);
        }
        if (response.statusCode() != 200) {
            throw new KeyPilotException(SdkErrorCode.JWKS_UNAVAILABLE, "JWKS endpoint returned status " + response.statusCode());
        }
        if (response.body().length > MAX_JWKS_RESPONSE_BYTES) {
            throw new KeyPilotException(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWKS response exceeds size limit");
        }
        String responseEtag = response.headers().firstValue("ETag").orElse("");
        return new FetchResult(parseJwks(response.body()), responseEtag, false);
    }

    /**
     * Description: Validates every JWK before returning an atomic replacement set.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   content: Raw JWKS JSON bytes.
     * Returns:
     *   Map: Complete validated key map.
     * Exceptions:
     *   KeyPilotException: JWKS_INVALID_RESPONSE when any key is invalid.
     */
    private Map<String, CachedKey> parseJwks(byte[] content) {
        JsonNode document;
        try {
            document = objectMapper.readTree(content);
        } catch (IOException error) {
            throw new KeyPilotException(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWKS JSON is invalid", error);
        }
        JsonNode keyNodes = document == null ? null : document.get("keys");
        if (keyNodes == null || !keyNodes.isArray()) {
            throw new KeyPilotException(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWKS keys is missing or invalid");
        }
        Map<String, CachedKey> parsedKeys = new HashMap<>();
        for (JsonNode keyNode : keyNodes) {
            ParsedKey parsedKey = parseJwk(keyNode);
            if (parsedKeys.putIfAbsent(parsedKey.kid(), parsedKey.cachedKey()) != null) {
                throw new KeyPilotException(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWKS contains duplicate kid");
            }
        }
        return parsedKeys;
    }

    /**
     * Description: Validates one RSA public JWK and constructs its public key.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   jwk: Parsed JWK JSON object.
     * Returns:
     *   ParsedKey: Key identifier and validated cached key.
     * Exceptions:
     *   KeyPilotException: JWKS_INVALID_RESPONSE when validation fails.
     */
    private ParsedKey parseJwk(JsonNode jwk) {
        if (jwk == null || !jwk.isObject()) {
            throw new KeyPilotException(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWK entry must be an object");
        }
        String keyType = text(jwk, "kty");
        String use = text(jwk, "use");
        String kid = text(jwk, "kid");
        if (!"RSA".equals(keyType) || !"sig".equals(use) || kid.isBlank() || !kid.equals(kid.trim())) {
            throw new KeyPilotException(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWK kty, use, or kid is invalid");
        }
        for (String privateField : PRIVATE_JWK_FIELDS) {
            if (jwk.has(privateField)) {
                throw new KeyPilotException(SdkErrorCode.JWKS_INVALID_RESPONSE, "private RSA JWK fields are not allowed");
            }
        }
        CryptoAlgorithm algorithm = algorithmFromJwk(text(jwk, "alg"));
        if (!config.getAllowedAlgorithms().contains(algorithm)) {
            throw new KeyPilotException(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWK algorithm is not allowed by verifier configuration");
        }
        try {
            byte[] modulusBytes = Base64.getUrlDecoder().decode(text(jwk, "n"));
            byte[] exponentBytes = Base64.getUrlDecoder().decode(text(jwk, "e"));
            BigInteger modulus = new BigInteger(1, modulusBytes);
            BigInteger exponent = new BigInteger(1, exponentBytes);
            int exponentValue = exponent.intValueExact();
            if (modulus.bitLength() < 2048 || exponentValue < 3 || exponentValue % 2 == 0) {
                throw new IllegalArgumentException("invalid RSA parameters");
            }
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
            RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
            return new ParsedKey(kid, new CachedKey(publicKey, algorithm));
        } catch (IllegalArgumentException | ArithmeticException | GeneralSecurityException error) {
            throw new KeyPilotException(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWK RSA parameters are invalid", error);
        }
    }

    /**
     * Description: Returns a textual JWK field or an empty string.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   node: JWK JSON object.
     *   name: Field name.
     * Returns:
     *   String: Text value or empty string.
     */
    private static String text(JsonNode node, String name) {
        JsonNode value = node.get(name);
        return value != null && value.isTextual() ? value.textValue() : "";
    }

    /**
     * Description: Maps a standard JWK algorithm string to a numeric enum.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   value: Standard JWK alg value.
     * Returns:
     *   CryptoAlgorithm: Mapped numeric algorithm.
     * Exceptions:
     *   KeyPilotException: JWKS_INVALID_RESPONSE for unsupported values.
     */
    private static CryptoAlgorithm algorithmFromJwk(String value) {
        return switch (value) {
            case "RS256" -> CryptoAlgorithm.RS256;
            case "PS256" -> CryptoAlgorithm.PS256;
            default -> throw new KeyPilotException(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWK algorithm is unsupported");
        };
    }

    /**
     * Description: Performs RS256 or PS256 verification over exact payload bytes.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   payload: Exact original business payload bytes.
     *   signatureBytes: Raw RSA signature bytes.
     *   publicKey: Validated RSA public key.
     *   algorithm: Requested numeric signature algorithm.
     * Returns: None.
     * Exceptions:
     *   KeyPilotException: SIGNATURE_INVALID or KEY_INVALID.
     */
    private static void verifyRsa(
            byte[] payload,
            byte[] signatureBytes,
            RSAPublicKey publicKey,
            CryptoAlgorithm algorithm
    ) {
        try {
            Signature verifier;
            if (algorithm == CryptoAlgorithm.RS256) {
                verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(publicKey);
            } else if (algorithm == CryptoAlgorithm.PS256) {
                verifier = Signature.getInstance("RSASSA-PSS");
                verifier.initVerify(publicKey);
                verifier.setParameter(new PSSParameterSpec(
                        "SHA-256",
                        "MGF1",
                        MGF1ParameterSpec.SHA256,
                        32,
                        1
                ));
            } else {
                throw new KeyPilotException(SdkErrorCode.ALGORITHM_NOT_ALLOWED, "algorithm is not supported");
            }
            verifier.update(payload);
            if (!verifier.verify(signatureBytes)) {
                throw new KeyPilotException(SdkErrorCode.SIGNATURE_INVALID, "signature verification failed");
            }
        } catch (KeyPilotException error) {
            throw error;
        } catch (GeneralSecurityException error) {
            throw new KeyPilotException(SdkErrorCode.KEY_INVALID, "RSA verification setup failed", error);
        }
    }

    /**
     * Description: Returns one cached key by identifier.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   kid: JWK key identifier.
     * Returns:
     *   CachedKey: Cached key or null.
     */
    private CachedKey getKey(String kid) {
        synchronized (cacheMonitor) {
            return keys.get(kid);
        }
    }

    /**
     * Description: Reports whether a key currently exists in the complete cache snapshot.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   kid: JWK key identifier.
     * Returns:
     *   boolean: True when cached.
     */
    boolean hasCachedKey(String kid) {
        return getKey(kid) != null;
    }

    /**
     * Description: Replaces the verifier clock for deterministic package tests.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   value: Test clock.
     * Returns: None.
     */
    void setClock(Clock value) {
        clock = value;
    }

    /**
     * Description: Stores one validated RSA public key and declared algorithm.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   publicKey: Constructed RSA public key.
     *   algorithm: Numeric JWK algorithm.
     * Returns: None.
     */
    private record CachedKey(RSAPublicKey publicKey, CryptoAlgorithm algorithm) {
    }

    /**
     * Description: Stores one parsed key identifier and cached key.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   kid: JWK key identifier.
     *   cachedKey: Validated cached key.
     * Returns: None.
     */
    private record ParsedKey(String kid, CachedKey cachedKey) {
    }

    /**
     * Description: Stores one JWKS HTTP fetch result.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   keys: Complete validated key set.
     *   etag: Response ETag.
     *   notModified: True for HTTP 304.
     * Returns: None.
     */
    private record FetchResult(Map<String, CachedKey> keys, String etag, boolean notModified) {
    }
}
