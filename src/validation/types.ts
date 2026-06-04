import type { SigningAlgorithm } from "../security/AlgorithmGuard";
import type { StandardClaims, TokenPayload } from "../core/types";

export type TokenPurpose = "access" | "id";

export interface VerificationPolicy {
  /** Strict algorithm allowlist for incoming tokens (defaults to library supported set). */
  allowedAlgorithms?: SigningAlgorithm[];
  /** Trusted iss (issuer) values — reject if iss is present and not listed. */
  trustedIssuers?: string[];
  /** Expected aud (audience) — string or list; reject if aud does not match. */
  audience?: string | string[];
  /** Allowed domains/origins for jku and x5u header URLs. */
  trustedKeySourceDomains?: string[];
  /** Clock skew tolerance in seconds for exp/nbf checks. */
  clockToleranceSeconds?: number;
  /** Require exp and nbf claims during verification. */
  requireTemporalClaims?: boolean;
  /** Optional revocation check after cryptographic validation. */
  isSessionRevoked?: (jti: string) => Promise<boolean>;
}

export interface VerifyOptions {
  /** Story 2.4: enforce access vs id token usage. */
  purpose?: TokenPurpose;
  /** Override configured audience for this verification. */
  audience?: string | string[];
  /** Override configured trusted issuers for this verification. */
  trustedIssuers?: string[];
  clockToleranceSeconds?: number;
  /** Override configured temporal-claim requirement for this verification. */
  requireTemporalClaims?: boolean;
  /** Developer hook after default validation succeeds. */
  onVerified?: (result: VerifyResult) => Promise<void> | void;
}

export interface VerifyResult {
  payload: TokenPayload;
  claims: StandardClaims & {
    exp?: number;
    iss?: string;
    aud?: string | string[];
    token_use?: string;
  };
  jti: string;
  purpose?: TokenPurpose;
}
