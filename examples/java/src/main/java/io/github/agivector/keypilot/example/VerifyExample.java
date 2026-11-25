/*
 * Description: Demonstrates minimal Java SDK verification against a running KeyPilot JWKS endpoint.
 * Author: vectorshi
 * Created: 2026-11-25
 */
package io.github.agivector.keypilot.example;

import io.github.agivector.keypilot.Config;
import io.github.agivector.keypilot.CryptoAlgorithm;
import io.github.agivector.keypilot.VerificationResult;
import io.github.agivector.keypilot.Verifier;

import java.util.Base64;
import java.util.Set;

/**
 * Description: Runs one environment-configurable KeyPilot Java verification example.
 * Author: vectorshi
 * Created: 2026-11-25
 * Parameters: None.
 * Returns: None.
 */
public final class VerifyExample {
    private static final String DEFAULT_PAYLOAD = "b3JkZXJfaWQ9S1AtMjAyNi0wMDAxJmFtb3VudD0xOTk5JmN1cnJlbmN5PUNOWQ";
    private static final String DEFAULT_SIGNATURE = "o_ZG9_pHw8Mx-EKyO-dkph6KFX0Z8xmPo_LbWyk1hCPsiaRIboCnqjv7ZiMTrbAqHVPddJLd_ILND30viCKLm5ixFUwVUGRwV1nEyQ4DdycNZoq0zem_vDC1KIwGU_6phN4VDbZ2mu1q1a20BOx7piIu8XxLj3mwXpnga8O8eVKcwYhP5KNx7oINWBeNjg2wmOryxWl55lIRS8xs7XBPlSH-13yb4zWmjRfYMfn10iMY2bFqDGNM8Qc8y0W8xOyg5iodh3R6_5RhIWE-Bl-cw1LBUO2Y3twQl6UVWpmbMNDsVxq6ZnBzHOOU9Qoo8h4PhxwTcHL9oamnEPDbn12ezw";

    /**
     * Description: Prevents construction of the command-line example type.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns: None.
     */
    private VerifyExample() {
    }

    /**
     * Description: Loads example inputs from environment variables and verifies one signature.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   args: Unused command-line arguments.
     * Returns: None.
     */
    public static void main(String[] args) {
        String issuer = environment("KEYPILOT_EXAMPLE_ISSUER", "vector-issuer");
        String jwksUrl = environment(
                "KEYPILOT_EXAMPLE_JWKS_URL",
                "http://127.0.0.1:8080/v1/issuers/vector-issuer/.well-known/jwks.json"
        );
        String kid = environment("KEYPILOT_EXAMPLE_KID", "vector-rs256-2026-01");
        CryptoAlgorithm algorithm = CryptoAlgorithm.fromCode(Integer.parseInt(environment(
                "KEYPILOT_EXAMPLE_ALGORITHM",
                Integer.toString(CryptoAlgorithm.RS256.getCode())
        )));
        byte[] payload = Base64.getUrlDecoder().decode(environment("KEYPILOT_EXAMPLE_PAYLOAD", DEFAULT_PAYLOAD));
        String signature = environment("KEYPILOT_EXAMPLE_SIGNATURE", DEFAULT_SIGNATURE);
        Verifier verifier = new Verifier(Config.builder()
                .issuer(issuer)
                .jwksUrl(jwksUrl)
                .allowedAlgorithms(Set.of(CryptoAlgorithm.RS256, CryptoAlgorithm.PS256))
                .build());
        VerificationResult result = verifier.verify(payload, signature, kid, algorithm);
        System.out.printf(
                "verification succeeded issuer=%s kid=%s algorithm=%d%n",
                result.issuer(), result.kid(), result.algorithm().getCode()
        );
    }

    /**
     * Description: Returns an environment value or its default.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   name: Environment variable name.
     *   fallback: Value used when the variable is empty.
     * Returns:
     *   String: Configured or default value.
     */
    private static String environment(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }
}
