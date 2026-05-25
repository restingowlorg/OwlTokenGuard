import type { ReferenceTokenEncoding } from "../generators/types";

/** JWT-style claims embedded on every issuance (Story 1.3). */
export interface StandardClaims {
  iat: number;
  nbf: number;
  jti: string;
}

/**
 * Server-owned session reference for termination/rotation.
 * Use jti from issuance (`TokenResult.claims`) or verified claims — never a raw JWT.
 */
export type SessionHandle = StandardClaims | { jti: string };

export type TokenPayload = Record<string, unknown>;

export interface GenerateOptions {
  /** Story 1.3: terminate previous session when rotating tokens. */
  previousSession?: SessionHandle;
  /** Override opaque reference encoding for this issuance. */
  referenceEncoding?: ReferenceTokenEncoding;
  /** Not-before offset in seconds from now. */
  nbfOffsetSeconds?: number;
}

export interface TokenResult {
  token: string;
  referenceToken?: string;
  claims: StandardClaims;
}
