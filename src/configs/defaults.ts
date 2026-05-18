export const DEFAULTS = {
  /** Default length (bytes) for newly issued opaque tokens. */
  OPAQUE_TOKEN_BYTES: 32,
  MIN_OPAQUE_TOKEN_BYTES: 16,
  /** Server secret for fingerprinting tokens at rest (HMAC-SHA256). */
  MIN_SIGNING_SECRET_BYTES: 32,
  HMAC_ALGORITHM: "sha256",
} as const;
