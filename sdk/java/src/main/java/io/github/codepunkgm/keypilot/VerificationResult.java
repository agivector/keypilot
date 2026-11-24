/*
 * Description: Defines the successful Java SDK verification result.
 * Author: vectorshi
 * Created: 2026-11-25
 */
package io.github.codepunkgm.keypilot;

/**
 * Description: Describes a successful local signature verification.
 * Author: vectorshi
 * Created: 2026-11-25
 * Parameters:
 *   valid: Always true for a returned result.
 *   issuer: Configured trusted issuer.
 *   kid: Actual key identifier.
 *   algorithm: Actual numeric signature algorithm.
 * Returns: None.
 */
public record VerificationResult(boolean valid, String issuer, String kid, CryptoAlgorithm algorithm) {
}
