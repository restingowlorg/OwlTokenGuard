import type { SigningAlgorithm } from "../security/AlgorithmGuard";

export const defaults = {
  /** Story 1.1: prefer asymmetric signing. */
  algorithm: "RS256" as SigningAlgorithm,
  opaqueEntropyBits: 128,
  referenceEncoding: "base64url" as const,
  minHmacSecretLength: 64,
} as const;
