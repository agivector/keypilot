/*
 * Description: Defines stable numeric signature algorithm values.
 * Author: vectorshi
 * Created: 2026-11-25
 */
package io.github.codepunkgm.keypilot;

/**
 * Description: Identifies a supported signature verification algorithm.
 * Author: vectorshi
 * Created: 2026-11-25
 * Parameters: None.
 * Returns: None.
 */
public enum CryptoAlgorithm {
    RS256(1001),
    PS256(1002);

    private final int code;

    /**
     * Description: Creates one stable numeric algorithm value.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   code: Stable numeric algorithm code.
     * Returns: None.
     */
    CryptoAlgorithm(int code) {
        this.code = code;
    }

    /**
     * Description: Returns the stable numeric algorithm code.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   int: Stable numeric algorithm code.
     */
    public int getCode() {
        return code;
    }

    /**
     * Description: Maps a stable numeric code to an algorithm enum.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   code: Numeric algorithm code.
     * Returns:
     *   CryptoAlgorithm: Matching algorithm.
     * Exceptions:
     *   IllegalArgumentException: Code is unsupported.
     */
    public static CryptoAlgorithm fromCode(int code) {
        for (CryptoAlgorithm algorithm : values()) {
            if (algorithm.code == code) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("unsupported CryptoAlgorithm code: " + code);
    }
}
