import type { SigningAlgorithm } from "../security/AlgorithmGuard";
import type { ReferenceTokenEncoding } from "../generators/types";
import type { PayloadCipher } from "../ciphering/PayloadCipher";
import type { ILogger } from "../utils/Logger";
import type {
  RefreshTokenConsumeContext,
  RefreshTokenIssuanceContext,
  SessionTerminateContext,
} from "../core/types";
import type { VerificationPolicy } from "../validation/types";

export type SigningKeyMaterial =
  | { type: "symmetric"; secret: string }
  | { type: "asymmetric"; privateKey: string; publicKey?: string };

export interface TokenConfig extends VerificationPolicy {
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
  /** Invoked when rotating sessions via `previousSession` or explicit termination. */
  onSessionTerminate: (context: SessionTerminateContext) => Promise<void>;
  /** Required `exp` claim offset in seconds from issuance. */
  expiresInSeconds: number;
  /** Issue a refresh JWT alongside each access token. */
  refreshTokenEnabled?: boolean;
  /** Refresh token `exp` offset in seconds from issuance. */
  refreshTokenExpiresInSeconds?: number;
  /**
   * Invoked after a refresh token is generated — persist it (e.g. database)
   * before the issuance result is returned to the caller.
   */
  onRefreshTokenIssued?: (
    context: RefreshTokenIssuanceContext,
  ) => Promise<void>;
  /**
   * Invoked at the start of `rotate()` — atomically mark the refresh token as consumed.
   * Return `true` to continue rotation, `false` if the token was already used.
   */
  consumeRefreshToken?: (
    context: RefreshTokenConsumeContext,
  ) => Promise<boolean>;
  /** Maximum JWT string size (bytes) accepted during verification (default: 8192). */
  maxTokenBytes?: number;
  debug?: boolean;
  customLogger?: ILogger;
}
