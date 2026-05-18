/**
 * Wiring options for `createTokenLibrary`.
 * Extend this shape as new token features are added (rotation, JWKS, etc.).
 */
export interface TokenLibraryOptions {
  /**
   * Secret used only on the server to derive stored fingerprints from raw tokens.
   * Must stay out of logs and client code.
   */
  signingSecret: Buffer;
  /** Bytes of entropy for each issued opaque token (default in `configs/defaults`). */
  opaqueTokenByteLength?: number;
}
