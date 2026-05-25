import { randomUUID } from "crypto";
import type { TokenConfig } from "../config/types";
import { defaults } from "../config/defaults";
import type {
  TokenPayload,
  GenerateOptions,
  TokenResult,
  SessionHandle,
} from "./types";
import { ReferenceTokenGenerator } from "../generators/ReferenceTokenGenerator";
import { resolveSigningMaterial, signJwt } from "../jwt/JwtSigner";
import { AlgorithmGuard, type SigningAlgorithm } from "../security/AlgorithmGuard";
import { TokenGenerationError } from "../errors/TokenGenerationError";
import { DefaultLogger, type ILogger } from "../utils/Logger";

function resolveSessionJti(session: SessionHandle): string {
  const jti = session.jti;
  if (typeof jti !== "string" || jti.length === 0) {
    throw new TokenGenerationError(
      "Session handle must include a non-empty jti from issuance or verified claims",
    );
  }
  return jti;
}

/**
 * Story 1.3: hardened issuance orchestration.
 */
export class TokenIssuer {
  private readonly logger: ILogger;
  private readonly referenceGenerator: ReferenceTokenGenerator;

  constructor(
    private readonly config: TokenConfig,
    dependencies?: { referenceGenerator?: ReferenceTokenGenerator },
  ) {
    this.logger = config.customLogger ?? new DefaultLogger(config.debug);
    this.referenceGenerator =
      dependencies?.referenceGenerator ?? new ReferenceTokenGenerator();
  }

  async issue(
    payload: TokenPayload,
    options: GenerateOptions = {},
  ): Promise<TokenResult> {
    if (options.previousSession) {
      await this.terminate(options.previousSession);
    }

    const algorithm = this.config.algorithm ?? defaults.algorithm;
    AlgorithmGuard.assertAllowed(algorithm);

    const now = Math.floor(Date.now() / 1000);
    const nbf = now + (options.nbfOffsetSeconds ?? 0);
    const jti = randomUUID();

    const standardClaims = { iat: now, nbf, jti };
    let jwtPayload: Record<string, unknown>;

    if (this.config.payloadCipher) {
      try {
        const encrypted = await this.config.payloadCipher.encrypt(
          JSON.stringify(payload),
        );
        jwtPayload = {
          ...standardClaims,
          enc: encrypted,
        };
      } catch (error) {
        this.logger.error("[TokenIssuer] payload encryption failed:", error);
        if (this.config.failOnCipherError !== false) {
          throw new TokenGenerationError("Payload encryption failed");
        }
        jwtPayload = { ...payload, ...standardClaims };
      }
    } else {
      jwtPayload = { ...payload, ...standardClaims };
    }

    if (this.config.expiresInSeconds !== undefined) {
      jwtPayload.exp = now + this.config.expiresInSeconds;
    }

    const signingMaterial = resolveSigningMaterial(
      algorithm as SigningAlgorithm,
      {
        hmacSecret: this.config.hmacSecret,
        signingKey: this.config.signingKey,
      },
    );

    const token = signJwt(jwtPayload, signingMaterial);

    const referenceEncoding =
      options.referenceEncoding ??
      this.config.referenceEncoding ??
      defaults.referenceEncoding;

    const referenceToken = this.referenceGenerator.generate({
      encoding: referenceEncoding,
      entropyBits: this.config.opaqueEntropyBits ?? defaults.opaqueEntropyBits,
    }).token;

    return {
      token,
      referenceToken,
      claims: standardClaims,
    };
  }

  /**
   * Revoke a session by server-owned jti or verified claims — not by raw JWT string.
   */
  async terminate(session: SessionHandle): Promise<void> {
    const jti = resolveSessionJti(session);

    if (this.config.onSessionTerminate) {
      await this.config.onSessionTerminate({ jti });
      this.logger.debug(`[TokenIssuer] terminated session jti=${jti}`);
    }
  }
}
