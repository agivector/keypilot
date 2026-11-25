/*
 * Description: Defines and validates configuration for the KeyPilot Java SDK.
 * Author: vectorshi
 * Created: 2026-11-25
 */
package io.github.codepunkgm.keypilot;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/**
 * Description: Binds a verifier to one trusted issuer and fixed JWKS URL.
 * Author: vectorshi
 * Created: 2026-11-25
 * Parameters: None.
 * Returns: None.
 */
public final class Config {
    private final String issuer;
    private final URI jwksUrl;
    private final Set<CryptoAlgorithm> allowedAlgorithms;
    private final Duration refreshInterval;
    private final Duration requestTimeout;
    private final Duration unknownKidCooldown;
    private final Duration maxStale;
    private final FailureMode failureMode;
    private final HttpClient httpClient;

    /**
     * Description: Validates and copies builder values.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   builder: Mutable configuration builder.
     * Returns: None.
     * Exceptions:
     *   KeyPilotException: CONFIGURATION_ERROR when any value is invalid.
     */
    private Config(Builder builder) {
        issuer = normalizeRequired(builder.issuer, "issuer");
        String rawUrl = normalizeRequired(builder.jwksUrl, "jwks_url");
        try {
            jwksUrl = URI.create(rawUrl);
        } catch (IllegalArgumentException error) {
            throw new KeyPilotException(SdkErrorCode.CONFIGURATION_ERROR, "jwks_url is invalid", error);
        }
        validateJwksUrl(jwksUrl);
        if (builder.allowedAlgorithms == null || builder.allowedAlgorithms.isEmpty()
                || builder.allowedAlgorithms.stream().anyMatch(Objects::isNull)) {
            throw new KeyPilotException(SdkErrorCode.CONFIGURATION_ERROR, "allowed_algorithms is required");
        }
        allowedAlgorithms = Set.copyOf(builder.allowedAlgorithms);
        refreshInterval = positive(builder.refreshInterval, "refresh_interval");
        requestTimeout = positive(builder.requestTimeout, "request_timeout");
        unknownKidCooldown = positive(builder.unknownKidCooldown, "unknown_kid_cooldown");
        maxStale = positive(builder.maxStale, "max_stale");
        if (maxStale.compareTo(refreshInterval) < 0) {
            throw new KeyPilotException(SdkErrorCode.CONFIGURATION_ERROR, "max_stale must not be less than refresh_interval");
        }
        if (builder.failureMode == null) {
            throw new KeyPilotException(SdkErrorCode.CONFIGURATION_ERROR, "failure_mode is invalid");
        }
        failureMode = builder.failureMode;
        httpClient = builder.httpClient == null
                ? HttpClient.newBuilder().connectTimeout(requestTimeout).build()
                : builder.httpClient;
    }

    /**
     * Description: Creates a configuration builder with secure defaults.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   Builder: New mutable configuration builder.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Description: Returns the trusted issuer identifier.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   String: Trusted issuer identifier.
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Description: Returns the fixed JWKS URL.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   URI: Validated JWKS URI.
     */
    public URI getJwksUrl() {
        return jwksUrl;
    }

    /**
     * Description: Returns the numeric algorithm whitelist.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   Set: Immutable allowed algorithm set.
     */
    public Set<CryptoAlgorithm> getAllowedAlgorithms() {
        return allowedAlgorithms;
    }

    /**
     * Description: Returns the normal cache refresh interval.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   Duration: Refresh interval.
     */
    public Duration getRefreshInterval() {
        return refreshInterval;
    }

    /**
     * Description: Returns the per-request JWKS timeout.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   Duration: Request timeout.
     */
    public Duration getRequestTimeout() {
        return requestTimeout;
    }

    /**
     * Description: Returns the unknown-kid refresh cooldown.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   Duration: Unknown-kid cooldown.
     */
    public Duration getUnknownKidCooldown() {
        return unknownKidCooldown;
    }

    /**
     * Description: Returns the maximum stale cache age.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   Duration: Maximum stale age.
     */
    public Duration getMaxStale() {
        return maxStale;
    }

    /**
     * Description: Returns the configured stale-cache policy.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   FailureMode: STRICT or AVAILABLE.
     */
    public FailureMode getFailureMode() {
        return failureMode;
    }

    /**
     * Description: Returns the HTTP client used for JWKS requests.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   HttpClient: Configured HTTP client.
     */
    public HttpClient getHttpClient() {
        return httpClient;
    }

    /**
     * Description: Trims and validates a required text value.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   value: Raw configuration text.
     *   name: Configuration field name.
     * Returns:
     *   String: Trimmed non-empty text.
     * Exceptions:
     *   KeyPilotException: CONFIGURATION_ERROR when empty.
     */
    private static String normalizeRequired(String value, String name) {
        String normalized = value == null ? "" : value.trim();
        if (normalized.isEmpty()) {
            throw new KeyPilotException(SdkErrorCode.CONFIGURATION_ERROR, name + " is required");
        }
        return normalized;
    }

    /**
     * Description: Validates that a duration is positive.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   value: Duration value.
     *   name: Configuration field name.
     * Returns:
     *   Duration: Validated duration.
     * Exceptions:
     *   KeyPilotException: CONFIGURATION_ERROR when non-positive.
     */
    private static Duration positive(Duration value, String name) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw new KeyPilotException(SdkErrorCode.CONFIGURATION_ERROR, name + " must be positive");
        }
        return value;
    }

    /**
     * Description: Enforces HTTPS except for loopback hosts used by local tests.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   uri: Parsed JWKS URI.
     * Returns: None.
     * Exceptions:
     *   KeyPilotException: CONFIGURATION_ERROR when unsafe or invalid.
     */
    private static void validateJwksUrl(URI uri) {
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new KeyPilotException(SdkErrorCode.CONFIGURATION_ERROR, "jwks_url is invalid");
        }
        if ("https".equalsIgnoreCase(scheme)) {
            return;
        }
        if ("http".equalsIgnoreCase(scheme) && isLoopbackHost(host)) {
            return;
        }
        throw new KeyPilotException(SdkErrorCode.CONFIGURATION_ERROR, "jwks_url must use HTTPS except for localhost tests");
    }

    /**
     * Description: Reports whether a host is safe for local HTTP tests.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   host: URI hostname without port.
     * Returns:
     *   boolean: True for localhost or loopback IP literals.
     */
    private static boolean isLoopbackHost(String host) {
        String normalized = host.toLowerCase();
        return "localhost".equals(normalized) || "::1".equals(normalized) || normalized.startsWith("127.");
    }

    /**
     * Description: Builds immutable KeyPilot configuration values.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns: None.
     */
    public static final class Builder {
        private String issuer;
        private String jwksUrl;
        private Set<CryptoAlgorithm> allowedAlgorithms;
        private Duration refreshInterval = Duration.ofMinutes(1);
        private Duration requestTimeout = Duration.ofSeconds(3);
        private Duration unknownKidCooldown = Duration.ofSeconds(30);
        private Duration maxStale = Duration.ofMinutes(15);
        private FailureMode failureMode = FailureMode.STRICT;
        private HttpClient httpClient;

        /**
         * Description: Sets the trusted issuer identifier.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   value: Trusted issuer identifier.
         * Returns:
         *   Builder: Current builder.
         */
        public Builder issuer(String value) {
            issuer = value;
            return this;
        }

        /**
         * Description: Sets the fixed JWKS URL.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   value: HTTPS or loopback HTTP URL.
         * Returns:
         *   Builder: Current builder.
         */
        public Builder jwksUrl(String value) {
            jwksUrl = value;
            return this;
        }

        /**
         * Description: Sets the numeric algorithm whitelist.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   value: Non-empty algorithm set.
         * Returns:
         *   Builder: Current builder.
         */
        public Builder allowedAlgorithms(Set<CryptoAlgorithm> value) {
            allowedAlgorithms = value;
            return this;
        }

        /**
         * Description: Sets the normal cache refresh interval.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   value: Positive duration.
         * Returns:
         *   Builder: Current builder.
         */
        public Builder refreshInterval(Duration value) {
            refreshInterval = value;
            return this;
        }

        /**
         * Description: Sets the per-request JWKS timeout.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   value: Positive duration.
         * Returns:
         *   Builder: Current builder.
         */
        public Builder requestTimeout(Duration value) {
            requestTimeout = value;
            return this;
        }

        /**
         * Description: Sets the unknown-kid refresh cooldown.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   value: Positive duration.
         * Returns:
         *   Builder: Current builder.
         */
        public Builder unknownKidCooldown(Duration value) {
            unknownKidCooldown = value;
            return this;
        }

        /**
         * Description: Sets the maximum stale cache age.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   value: Positive duration not below refresh interval.
         * Returns:
         *   Builder: Current builder.
         */
        public Builder maxStale(Duration value) {
            maxStale = value;
            return this;
        }

        /**
         * Description: Sets the stale-cache failure policy.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   value: STRICT or AVAILABLE.
         * Returns:
         *   Builder: Current builder.
         */
        public Builder failureMode(FailureMode value) {
            failureMode = value;
            return this;
        }

        /**
         * Description: Sets a caller-managed HTTP client.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters:
         *   value: HTTP client used for JWKS requests.
         * Returns:
         *   Builder: Current builder.
         */
        public Builder httpClient(HttpClient value) {
            httpClient = value;
            return this;
        }

        /**
         * Description: Validates and builds immutable configuration.
         * Author: vectorshi
         * Created: 2026-11-25
         * Parameters: None.
         * Returns:
         *   Config: Validated immutable configuration.
         */
        public Config build() {
            return new Config(this);
        }
    }
}
