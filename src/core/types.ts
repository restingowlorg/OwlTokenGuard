import type { ReferenceTokenEncoding } from "../generators/types";

/** JWT-style claims embedded on every issuance (Story 1.3). */
export interface StandardClaims {
  iat: number;
  nbf: number;
  jti: string;
}

/**
 * Server-owned session reference for termination/rotation.
 * Use jti from issuance (`AccessTokenResult.claims`) or verified claims — never a raw JWT.
 */
export type SessionHandle = StandardClaims | { jti: string };

export type TokenPayload = Record<string, unknown>;

/** Context passed to `onRefreshTokenIssued` for server-side persistence. */
export interface RefreshTokenIssuedContext {
  refreshToken: string;
  refreshClaims: StandardClaims;
  accessClaims: StandardClaims;
  payload: TokenPayload;
  /** Refresh token expiry as Unix seconds. */
  expiresAt: number;
}

export interface AccessTokenOptions {
  /** Terminate a prior session when rotating access tokens. */
  previousSession?: SessionHandle;
  /** Not-before offset in seconds from now. */
  nbfOffsetSeconds?: number;
  /** Override configured refresh-token persistence hook for this issuance. */
  onRefreshTokenIssued?: (
    context: RefreshTokenIssuedContext,
  ) => Promise<void> | void;
}

export interface ReferenceIssuanceOptions {
  /** Override opaque reference encoding for this issuance. */
  referenceEncoding?: ReferenceTokenEncoding;
}

/** Options for combined JWT + reference issuance (`generate`). */
export interface GenerateOptions
  extends AccessTokenOptions,
    ReferenceIssuanceOptions {}

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
