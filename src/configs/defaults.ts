export const DEFAULTS = {
  ENCRYPTION_ALGORITHM: "aes-256-gcm",
  IV_LENGTH: 12,          // Recommended for GCM
  KEY_LENGTH: 32,         // 256-bit
  HASH_ITERATIONS: 100_000,
  HASH_KEY_LENGTH: 32,
  HASH_DIGEST: "sha256"
};
