import type { SigningAlgorithm } from "../security/AlgorithmGuard";
import type { ReferenceTokenEncoding } from "../generators/types";
import type { PayloadCipher } from "../ciphering/PayloadCipher";
import type { ILogger } from "../utils/Logger";

export type SigningKeyMaterial =
  | { type: "symmetric"; secret: string }
  | { type: "asymmetric"; privateKey: string; publicKey?: string };

export interface TokenConfig {
  /** Preferred: RS256 or ES256. HS256/HS512 require high-entropy secrets. */
  algorithm?: SigningAlgorithm;
  signingKey?: SigningKeyMaterial;
  /** Minimum 64 characters for HS256/HS512. */
  hmacSecret?: string;
  /** Opaque reference token output format. */
  referenceEncoding?: ReferenceTokenEncoding;
  /** Minimum entropy in bits for opaque tokens (default: 128). */
  opaqueEntropyBits?: number;
  /** Optional AES-256-GCM payload encryption before signing. */
  payloadCipher?: PayloadCipher;
  failOnCipherError?: boolean;
  /** Invoked when rotating sessions via `previousToken`. */
  onSessionTerminate?: (context: {
    jti: string;
    token: string;
  }) => Promise<void>;
  /** Optional `exp` claim offset in seconds from issuance. */
  expiresInSeconds?: number;
  debug?: boolean;
  customLogger?: ILogger;
}
