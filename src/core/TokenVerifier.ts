import type { TokenConfig } from "../config/types";
import type { VerifyOptions, VerifyResult, TokenPurpose } from "../validation/types";
import { verifyJwtSignatureFirst } from "../jwt/JwtVerifier";
import { TokenVerificationError } from "../errors/TokenVerificationError";
import type { EncryptedPayload } from "../ciphering/types";

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

type DeclaredTokenType = TokenPurpose | "refresh";

function normalizeDeclaredTokenType(value: string): DeclaredTokenType | undefined {
  if (value === "access" || value === "at+jwt") {
    return "access";
  }
  if (value === "id" || value === "id+jwt") {
    return "id";
  }
  if (value === "refresh") {
    return "refresh";
  }
  return undefined;
}

/**
 * Epic 2: fail-shut verification gatekeeper (ASVS 9.1 & 9.2).
 */
export class TokenVerifier {
  constructor(private readonly config: TokenConfig) {}

  async verify(token: string, options: VerifyOptions = {}): Promise<VerifyResult> {
    const { header, payload: rawPayload } = verifyJwtSignatureFirst(
      token,
      this.config,
    );
    const payload = await this.resolvePayload(rawPayload);
    this.assertTemporalClaims(payload, options);
    this.assertIssuer(payload, options);
    this.assertAudience(payload, options);
    this.assertPurpose(payload, header, options.purpose);

    const jti = payload.jti;
    if (typeof jti !== "string" || jti.length === 0) {
      throw new TokenVerificationError("JWT is missing required jti claim");
    }

    if (this.config.isSessionRevoked) {
      const revoked = await this.config.isSessionRevoked(jti);
      if (revoked) {
        throw new TokenVerificationError("Session has been revoked");
      }
    }

    const claims = this.extractStandardClaims(payload);
    const result: VerifyResult = {
      payload,
      claims,
      jti,
      purpose: options.purpose,
    };

    if (options.onVerified) {
      await options.onVerified(result);
    }

    return result;
  }

  private async resolvePayload(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    if (payload.enc !== undefined) {
      if (!this.config.payloadCipher) {
        throw new TokenVerificationError(
          "Encrypted payload present but no payloadCipher configured",
        );
      }
      const decrypted = await this.config.payloadCipher.decrypt(
        payload.enc as EncryptedPayload,
      );
      const parsed = JSON.parse(decrypted) as Record<string, unknown>;
      return { ...parsed, ...this.extractStandardClaims(payload) };
    }
    return payload;
  }

  private assertTemporalClaims(
    payload: Record<string, unknown>,
    options: VerifyOptions,
  ): void {
    const requireTemporal =
      options.requireTemporalClaims ??
      this.config.requireTemporalClaims ??
      (options.purpose === "access" || options.purpose === "refresh");
    const tolerance =
      options.clockToleranceSeconds ??
      this.config.clockToleranceSeconds ??
      0;
    const now = nowSeconds();

    const nbf = payload.nbf;
    const exp = payload.exp;

    if (requireTemporal) {
      if (typeof exp !== "number") {
        throw new TokenVerificationError("JWT is missing required exp claim");
      }
      if (typeof nbf !== "number") {
        throw new TokenVerificationError("JWT is missing required nbf claim");
      }
    }

    if (typeof nbf === "number" && now + tolerance < nbf) {
      throw new TokenVerificationError("Token is not yet valid (nbf)");
    }

    if (typeof exp === "number" && now - tolerance >= exp) {
      throw new TokenVerificationError("Token has expired (exp)");
    }
  }

  private assertIssuer(
    payload: Record<string, unknown>,
    options: VerifyOptions,
  ): void {
    const trusted =
      options.trustedIssuers ?? this.config.trustedIssuers ?? [];
    if (trusted.length === 0) return;

    const iss = payload.iss;
    if (typeof iss !== "string" || !trusted.includes(iss)) {
      throw new TokenVerificationError("Untrusted token issuer (iss)");
    }
  }

  private assertAudience(
    payload: Record<string, unknown>,
    options: VerifyOptions,
  ): void {
    const expected = options.audience ?? this.config.audience;
    if (expected === undefined) return;

    const aud = payload.aud;
    const expectedList = Array.isArray(expected) ? expected : [expected];

    if (typeof aud === "string") {
      if (!expectedList.includes(aud)) {
        throw new TokenVerificationError("Token audience mismatch (aud)");
      }
      return;
    }

    if (Array.isArray(aud)) {
      const match = aud.some(
        (value) => typeof value === "string" && expectedList.includes(value),
      );
      if (!match) {
        throw new TokenVerificationError("Token audience mismatch (aud)");
      }
      return;
    }

    throw new TokenVerificationError("Token is missing required aud claim");
  }

  /** Story 2.4: prevent ID tokens from being used as access tokens. */
  private assertPurpose(
    payload: Record<string, unknown>,
    header: Record<string, unknown>,
    purpose?: TokenPurpose,
  ): void {
    if (!purpose) return;

    const tokenUse =
      typeof payload.token_use === "string"
        ? payload.token_use.toLowerCase()
        : undefined;
    const payloadTyp =
      typeof payload.typ === "string" ? payload.typ.toLowerCase() : undefined;
    const headerTyp =
      typeof header.typ === "string" ? header.typ.toLowerCase() : undefined;

    const rawEffective = tokenUse ?? payloadTyp ?? headerTyp;
    const effective = rawEffective
      ? normalizeDeclaredTokenType(rawEffective)
      : undefined;

    if (!effective) {
      throw new TokenVerificationError(
        "Token type is required when purpose is enforced",
      );
    }

    if (purpose === "access" && effective === "id") {
      throw new TokenVerificationError(
        "ID token cannot be used as an access token",
      );
    }

    if (purpose === "id" && effective === "access") {
      throw new TokenVerificationError(
        "Access token cannot be used as an ID token",
      );
    }

    if (purpose === "refresh" && effective !== "refresh") {
      throw new TokenVerificationError(
        "Token cannot be used as a refresh token",
      );
    }
  }

  private extractStandardClaims(
    payload: Record<string, unknown>,
  ): VerifyResult["claims"] {
    const iat = payload.iat;
    const nbf = payload.nbf;
    const jti = payload.jti;

    if (
      typeof iat !== "number" ||
      typeof nbf !== "number" ||
      typeof jti !== "string"
    ) {
      throw new TokenVerificationError(
        "JWT is missing required standard claims (iat, nbf, jti)",
      );
    }

    return {
      iat,
      nbf,
      jti,
      exp: typeof payload.exp === "number" ? payload.exp : undefined,
      iss: typeof payload.iss === "string" ? payload.iss : undefined,
      aud: payload.aud as string | string[] | undefined,
      token_use:
        typeof payload.token_use === "string" ? payload.token_use : undefined,
    };
  }
}
