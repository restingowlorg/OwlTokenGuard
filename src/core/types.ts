import type { ReferenceTokenEncoding } from "../generators/types";

/** JWT claim name for last full reauthentication (Unix seconds). */
export const REAUTH_AT_CLAIM = "reauth_at";

/** JWT-style claims embedded on every issuance (Story 1.3). */
export interface StandardClaims {
  iat: number;
  nbf: number;
  jti: string;
  /** Present when stamped at issuance — last email/MFA reauthentication time. */
  reauth_at?: number;
}

/**
 * Server-owned session reference for termination/rotation.
 * Use jti from issuance (`AccessTokenResult.claims`) or verified claims — never a raw JWT.
 */
export type SessionHandle = StandardClaims | { jti: string };

/** Context passed to `onSessionTerminate` for session removal or cutoff invalidation. */
export interface SessionTerminateContext {
  jti: string;
  iat?: number;
  sub?: string;
  /**
   * When set, persist this cutoff so verification rejects tokens with `iat` strictly before it.
   * Use `Math.floor(Date.now() / 1000)` for logout-all-devices policies.
   */
  invalidateBefore?: number;
}

export interface TerminateOptions {
  sub?: string;
  invalidateBefore?: number;
}

export type TokenPayload = Record<string, unknown>;

/** Context passed to `onRefreshTokenIssued` for database persistence. */
export interface RefreshTokenIssuanceContext {
  refreshToken: string;
  refreshClaims: StandardClaims;
  accessClaims: StandardClaims;
  payload: TokenPayload;
  /** Refresh token `exp` as a Unix timestamp in seconds. */
  expiresAt: number;
}

export interface AccessTokenOptions {
  /** Terminate a prior session when rotating access tokens. */
  previousSession?: SessionHandle;
  /** Not-before offset in seconds from now. */
  nbfOffsetSeconds?: number;
  /**
   * Freshness marker (Unix seconds) stamped as `reauth_at` on access and refresh tokens.
   * Set after email verification or MFA so older sessions can be rejected on verify.
   */
  reauthAt?: number;
}

export interface ReferenceIssuanceOptions {
  /** Override opaque reference encoding for this issuance. */
  referenceEncoding?: ReferenceTokenEncoding;
}

/** Options for combined JWT + reference issuance (`generate`). */
export interface GenerateOptions
  extends AccessTokenOptions, ReferenceIssuanceOptions {}

/** Signed JWT access token with standard claims. */
export interface AccessTokenResult {
  token: string;
  claims: StandardClaims;
  /** Present when `refreshTokenEnabled` is true in config. */
  refreshToken?: string;
  refreshClaims?: StandardClaims;
}

/** Opaque backend session identifier (ASVS 7.2.3). */
export interface SessionReferenceResult {
  referenceToken: string;
  encoding: ReferenceTokenEncoding;
  entropyBits: number;
}

/** Combined issuance result — use when both access and reference tokens are required. */
export interface TokenResult extends AccessTokenResult {
  referenceToken: string;
}

/** Context passed to `consumeRefreshToken` during rotation. */
export interface RefreshTokenConsumeContext {
  jti: string;
  sub: string;
  exp: number;
  iat: number;
}

export interface RotateOptions {
  /** Not-before offset in seconds from now for the new access token. */
  nbfOffsetSeconds?: number;
}

export interface RevokeTokenOptions {
  /** Enforce token_use during verification (e.g. `"refresh"` for logout cookies). */
  purpose?: "access" | "id" | "refresh";
  /**
   * When set, passed to `onSessionTerminate` to invalidate tokens issued before this Unix timestamp.
   * Omit to revoke only the presented token's `jti`.
   */
  invalidateBefore?: number;
}

/** RFC 6749 token response — return directly from `POST /auth/refresh`. */
export interface OAuthTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
}

/** Result of `rotate()` — library fields plus OAuth-standard `oauth` payload. */
export interface RotateResult extends AccessTokenResult {
  refreshToken: string;
  refreshClaims: StandardClaims;
  previousRefreshJti: string;
  oauth: OAuthTokenResponse;
}
