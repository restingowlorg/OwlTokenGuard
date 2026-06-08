import type { SigningAlgorithm } from "../security/AlgorithmGuard";
import type { ReferenceTokenEncoding } from "../generators/types";
import type { PayloadCipher } from "../ciphering/PayloadCipher";
import type { ILogger } from "../utils/Logger";
import type { VerificationPolicy } from "../validation/types";
import type { RefreshTokenIssuedContext } from "../core/types";

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
  /** Invoked when rotating sessions via `previousSession`. */
  onSessionTerminate?: (context: { jti: string }) => Promise<void>;
  /**
   * Invoked after a refresh token is generated — persist it server-side (e.g. database).
   * Only runs when `refreshTokenEnabled` is true.
   */
  onRefreshTokenIssued?: (
    context: RefreshTokenIssuedContext,
  ) => Promise<void> | void;
  /** Required `exp` claim offset in seconds from issuance. */
  expiresInSeconds: number;
  /** Issue a refresh JWT alongside each access token. */
  refreshTokenEnabled?: boolean;
  /** Refresh token `exp` offset in seconds from issuance. */
  refreshTokenExpiresInSeconds?: number;
  debug?: boolean;
  customLogger?: ILogger;
}
