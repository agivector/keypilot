/*
 * Description: Defines stable numeric cache failure policy values.
 * Author: vectorshi
 * Created: 2026-11-25
 */
package io.github.agivector.keypilot;

/**
 * Description: Controls stale-cache behavior when JWKS refresh fails.
 * Author: vectorshi
 * Created: 2026-11-25
 * Parameters: None.
 * Returns: None.
 */
public enum FailureMode {
    STRICT(1),
    AVAILABLE(2);

    private final int code;

    /**
     * Description: Creates one stable numeric failure mode.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   code: Stable numeric failure mode code.
     * Returns: None.
     */
    FailureMode(int code) {
        this.code = code;
    }

    /**
     * Description: Returns the stable numeric failure mode code.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   int: Stable numeric failure mode code.
     */
    public int getCode() {
        return code;
    }
}
