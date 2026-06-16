import type { SigningAlgorithm } from "../security/AlgorithmGuard";
import type { StandardClaims, TokenPayload } from "../core/types";

export type TokenPurpose = "access" | "id" | "refresh";

/** Context passed to `isSessionRevoked` during verification. */
export interface SessionRevocationContext {
  jti: string;
  /** Token issued-at (Unix seconds). */
  iat: number;
  sub?: string;
  nbf?: number;
  exp?: number;
  /** Last reauthentication time from the `reauth_at` claim, when present. */
  reauthAt?: number;
}

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
  /**
   * Returns the earliest valid `iat` (Unix seconds) for the subject.
   * Tokens with `iat` strictly before this value are rejected during verification.
   */
  getTokensInvalidBefore?: (sub: string) => Promise<number | undefined>;
  /**
   * When true, tokens must include a `reauth_at` claim during verification.
   */
  requireReauthAtClaim?: boolean;
  /**
   * Returns the minimum valid `reauth_at` (Unix seconds) for the subject.
   * Tokens with a lower `reauth_at` are rejected after email or MFA changes.
   */
  getMinimumReauthAt?: (sub: string) => Promise<number | undefined>;
  /** Optional per-token revocation check after cryptographic validation. */
  isSessionRevoked?: (context: SessionRevocationContext) => Promise<boolean>;
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
  /** Override configured `reauth_at` requirement for this verification. */
  requireReauthAtClaim?: boolean;
  /** Per-request minimum `reauth_at` (Unix seconds) — overrides `getMinimumReauthAt`. */
  minimumReauthAt?: number;
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
    reauth_at?: number;
  };
  jti: string;
  purpose?: TokenPurpose;
}
