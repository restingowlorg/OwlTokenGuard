import type { TokenConfig } from "../config/types";
import type { TokenIssuer } from "./TokenIssuer";
import type { TokenTerminator } from "./TokenTerminator";
import type { TokenVerifier } from "./TokenVerifier";
import type {
  OAuthTokenResponse,
  RotateOptions,
  RotateResult,
  TokenPayload,
} from "./types";
import { TokenGenerationError } from "../errors/TokenGenerationError";
import { TokenVerificationError } from "../errors/TokenVerificationError";

const ROTATABLE_PAYLOAD_EXCLUDE = new Set([
  "iat",
  "nbf",
  "jti",
  "exp",
  "iss",
  "aud",
  "token_use",
  "typ",
  "enc",
]);

function extractRotatablePayload(payload: TokenPayload): TokenPayload {
  const result: TokenPayload = {};
  for (const [key, value] of Object.entries(payload)) {
    if (!ROTATABLE_PAYLOAD_EXCLUDE.has(key)) {
      result[key] = value;
    }
  }
  return result;
}

function buildOAuthTokenResponse(
  accessToken: string,
  refreshToken: string,
  expiresInSeconds: number,
): OAuthTokenResponse {
  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresInSeconds,
    refresh_token: refreshToken,
  };
}

/**
 * Refresh Token Rotation — verify a refresh JWT and issue a new access/refresh pair.
 */
export class TokenRotator {
  constructor(
    private readonly config: TokenConfig,
    private readonly issuer: TokenIssuer,
    private readonly verifier: TokenVerifier,
    private readonly terminator: TokenTerminator,
  ) {}

  async rotate(
    refreshToken: string,
    options: RotateOptions = {},
  ): Promise<RotateResult> {
    if (!this.config.refreshTokenEnabled) {
      throw new TokenGenerationError(
        "rotate() requires refreshTokenEnabled in TokenConfig",
      );
    }

    const verified = await this.verifier.verify(refreshToken, {
      purpose: "refresh",
    });

    const sub = verified.payload.sub;
    if (typeof sub !== "string" || sub.length === 0) {
      throw new TokenVerificationError(
        "Refresh token is missing required sub claim",
      );
    }

    const exp = verified.claims.exp;
    if (typeof exp !== "number") {
      throw new TokenVerificationError(
        "Refresh token is missing required exp claim",
      );
    }

    if (this.config.consumeRefreshToken) {
      const allowed = await this.config.consumeRefreshToken({
        jti: verified.jti,
        sub,
        exp,
        iat: verified.claims.iat,
      });
      if (!allowed) {
        throw new TokenVerificationError("Refresh token has already been used");
      }
    }

    const payload = extractRotatablePayload(verified.payload);
    const issued = await this.issuer.issueAccessToken(payload, {
      nbfOffsetSeconds: options.nbfOffsetSeconds,
    });

    if (!issued.refreshToken || !issued.refreshClaims) {
      throw new TokenGenerationError(
        "rotate() did not produce a refresh token — ensure refreshTokenEnabled is true",
      );
    }

    await this.terminator.terminate(verified.claims);

    return {
      token: issued.token,
      claims: issued.claims,
      refreshToken: issued.refreshToken,
      refreshClaims: issued.refreshClaims,
      previousRefreshJti: verified.jti,
      oauth: buildOAuthTokenResponse(
        issued.token,
        issued.refreshToken,
        this.config.expiresInSeconds,
      ),
    };
  }
}
