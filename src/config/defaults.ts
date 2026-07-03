import type { SigningAlgorithm } from "../security/AlgorithmGuard";

/** Default maximum JWT string size accepted during verification (8 KB). */
export const DEFAULT_MAX_JWT_BYTES = 8192;

export const defaults = {
  /** Story 1.1: prefer asymmetric signing. */
  algorithm: "RS256" as SigningAlgorithm,
  opaqueEntropyBits: 128,
  referenceEncoding: "base64url" as const,
  minHmacSecretLength: 64,
  maxTokenBytes: DEFAULT_MAX_JWT_BYTES,
} as const;
