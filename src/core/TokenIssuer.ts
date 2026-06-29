import { randomUUID } from "crypto";
import type { TokenConfig } from "../config/types";
import { defaults } from "../config/defaults";
import type {
  TokenPayload,
  GenerateOptions,
  AccessTokenOptions,
  ReferenceIssuanceOptions,
  TokenResult,
  AccessTokenResult,
  SessionReferenceResult,
  StandardClaims,
} from "./types";
import { REAUTH_AT_CLAIM } from "./types";
import { ReferenceTokenGenerator } from "../generators/ReferenceTokenGenerator";
import { resolveSigningMaterial, signJwt } from "../jwt/JwtSigner";
import {
  AlgorithmGuard,
  type SigningAlgorithm,
} from "../security/AlgorithmGuard";
import { TokenGenerationError } from "../errors/TokenGenerationError";
import { DefaultLogger, type ILogger } from "../utils/Logger";
import type { TokenTerminator } from "./TokenTerminator";

/**
 * Story 1.3: hardened issuance orchestration.
 */
export class TokenIssuer {
  private readonly logger: ILogger;
  private readonly referenceGenerator: ReferenceTokenGenerator;
  private readonly terminator?: TokenTerminator;

  constructor(
    private readonly config: TokenConfig,
    dependencies?: {
      referenceGenerator?: ReferenceTokenGenerator;
      terminator?: TokenTerminator;
    },
  ) {
    this.logger = config.customLogger ?? new DefaultLogger(config.debug);
    this.referenceGenerator =
      dependencies?.referenceGenerator ?? new ReferenceTokenGenerator();
    this.terminator = dependencies?.terminator;
  }

  /** Issue a signed JWT access token only. */
  async issueAccessToken(
    payload: TokenPayload,
    options: AccessTokenOptions = {},
  ): Promise<AccessTokenResult> {
    if (options.previousSession) {
      await this.terminator?.terminate(options.previousSession);
    }

    const algorithm = this.config.algorithm ?? defaults.algorithm;
    AlgorithmGuard.assertAllowed(algorithm);

    const now = Math.floor(Date.now() / 1000);
    const nbf = now + (options.nbfOffsetSeconds ?? 0);
    const jti = randomUUID();
    const standardClaims: StandardClaims = { iat: now, nbf, jti };
    applyConfiguredRegisteredClaims(standardClaims, this.config);
    const reauthAt = resolveReauthAt(payload, options);

    let jwtPayload: Record<string, unknown>;
    if (this.config.payloadCipher) {
      try {
        const encrypted = await this.config.payloadCipher.encrypt(
          JSON.stringify(payload),
        );
        jwtPayload = { ...standardClaims, enc: encrypted, token_use: "access" };
      } catch (error) {
        this.logger.error("[TokenIssuer] payload encryption failed:", error);
        if (this.config.failOnCipherError !== false) {
          throw new TokenGenerationError("Payload encryption failed");
        }
        jwtPayload = { ...payload, ...standardClaims, token_use: "access" };
      }
    } else {
      jwtPayload = { ...payload, ...standardClaims, token_use: "access" };
    }
    applyConfiguredRegisteredClaims(jwtPayload, this.config);

    if (this.config.expiresInSeconds !== undefined) {
      jwtPayload.exp = now + this.config.expiresInSeconds;
    }

    if (reauthAt !== undefined) {
      jwtPayload[REAUTH_AT_CLAIM] = reauthAt;
      standardClaims.reauth_at = reauthAt;
    }

    const signingMaterial = resolveSigningMaterial(
      algorithm as SigningAlgorithm,
      {
        hmacSecret: this.config.hmacSecret,
        signingKey: this.config.signingKey,
      },
    );

    const result: AccessTokenResult = {
      token: signJwt(jwtPayload, signingMaterial),
      claims: standardClaims,
    };

    if (this.config.refreshTokenEnabled) {
      const refresh = this.issueRefreshToken(
        payload,
        signingMaterial,
        reauthAt,
      );
      result.refreshToken = refresh.refreshToken;
      result.refreshClaims = refresh.refreshClaims;

      if (this.config.onRefreshTokenIssued) {
        try {
          await this.config.onRefreshTokenIssued({
            refreshToken: refresh.refreshToken,
            refreshClaims: refresh.refreshClaims,
            accessClaims: standardClaims,
            payload,
            expiresAt: refresh.expiresAt,
          });
        } catch (error) {
          this.logger.error(
            "[TokenIssuer] refresh token persistence failed:",
            error,
          );
          throw new TokenGenerationError("Refresh token persistence failed");
        }
      }
    }

    return result;
  }

  private issueRefreshToken(
    payload: TokenPayload,
    signingMaterial: ReturnType<typeof resolveSigningMaterial>,
    reauthAt?: number,
  ): {
    refreshToken: string;
    refreshClaims: StandardClaims;
    expiresAt: number;
  } {
    const expiresIn = this.config.refreshTokenExpiresInSeconds;
    if (expiresIn === undefined) {
      throw new TokenGenerationError(
        "refreshTokenExpiresInSeconds is required when refresh tokens are enabled",
      );
    }

    const now = Math.floor(Date.now() / 1000);
    const jti = randomUUID();
    const expiresAt = now + expiresIn;
    const refreshClaims: StandardClaims = { iat: now, nbf: now, jti };
    applyConfiguredRegisteredClaims(refreshClaims, this.config);
    const jwtPayload: Record<string, unknown> = {
      ...refreshClaims,
      token_use: "refresh",
      exp: expiresAt,
    };
    applyConfiguredRegisteredClaims(jwtPayload, this.config);

    if (reauthAt !== undefined) {
      jwtPayload[REAUTH_AT_CLAIM] = reauthAt;
      refreshClaims.reauth_at = reauthAt;
    }

    if (typeof payload.sub === "string") {
      jwtPayload.sub = payload.sub;
    }

    return {
      refreshToken: signJwt(jwtPayload, signingMaterial),
      refreshClaims,
      expiresAt,
    };
  }

  /** Issue an opaque reference token only (backend-stored sessions). */
  issueReferenceToken(
    options: ReferenceIssuanceOptions = {},
  ): SessionReferenceResult {
    const referenceEncoding =
      options.referenceEncoding ??
      this.config.referenceEncoding ??
      defaults.referenceEncoding;

    const result = this.referenceGenerator.generate({
      encoding: referenceEncoding,
      entropyBits: this.config.opaqueEntropyBits ?? defaults.opaqueEntropyBits,
    });

    return {
      referenceToken: result.token,
      encoding: result.encoding,
      entropyBits: result.entropyBits,
    };
  }

  /**
   * Compatibility wrapper: issues both access JWT and opaque reference token.
   * Prefer {@link issueAccessToken} or {@link issueReferenceToken} when only one is needed.
   */
  async issue(
    payload: TokenPayload,
    options: GenerateOptions = {},
  ): Promise<TokenResult> {
    const access = await this.issueAccessToken(payload, options);
    const reference = this.issueReferenceToken({
      referenceEncoding: options.referenceEncoding,
    });

    return {
      ...access,
      referenceToken: reference.referenceToken,
    };
  }
}

function applyConfiguredRegisteredClaims(
  claims: { iss?: string; aud?: string | string[] },
  config: TokenConfig,
): void {
  if (config.issuer !== undefined) {
    claims.iss = config.issuer;
  }
  if (config.audience !== undefined) {
    claims.aud = config.audience;
  }
}

function resolveReauthAt(
  payload: TokenPayload,
  options: AccessTokenOptions,
): number | undefined {
  if (options.reauthAt !== undefined) {
    return options.reauthAt;
  }
  const fromPayload = payload[REAUTH_AT_CLAIM];
  return typeof fromPayload === "number" ? fromPayload : undefined;
}
