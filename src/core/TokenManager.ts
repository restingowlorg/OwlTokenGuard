import { TokenIssuer } from "./TokenIssuer";
import { TokenRotator } from "./TokenRotator";
import { TokenVerifier } from "./TokenVerifier";
import type { TokenConfig } from "../config/types";
import { validateConfig } from "../config/validation";
import type {
  TokenPayload,
  GenerateOptions,
  AccessTokenOptions,
  ReferenceIssuanceOptions,
  TokenResult,
  AccessTokenResult,
  SessionReferenceResult,
  SessionHandle,
  RotateOptions,
  RotateResult,
} from "./types";
import type { VerifyOptions, VerifyResult } from "../validation/types";

/**
 * Token management API. Instantiate only via {@link createTokenManager}.
 */
export class TokenManager {
  private readonly issuer: TokenIssuer;
  private readonly verifier: TokenVerifier;
  private readonly rotator: TokenRotator;

  private constructor(
    public readonly config: TokenConfig,
    dependencies?: {
      issuer?: TokenIssuer;
      verifier?: TokenVerifier;
      rotator?: TokenRotator;
    },
  ) {
    this.issuer = dependencies?.issuer ?? new TokenIssuer(config);
    this.verifier = dependencies?.verifier ?? new TokenVerifier(config);
    this.rotator =
      dependencies?.rotator ??
      new TokenRotator(config, this.issuer, this.verifier);
  }

  /** Validated construction — prefer `createTokenManager()` from the factory. */
  static create(
    config: TokenConfig,
    dependencies?: {
      issuer?: TokenIssuer;
      verifier?: TokenVerifier;
      rotator?: TokenRotator;
    },
  ): TokenManager {
    validateConfig(config);
    return new TokenManager(config, dependencies);
  }

  async generateAccessToken(
    payload: TokenPayload,
    options?: AccessTokenOptions,
  ): Promise<AccessTokenResult> {
    return this.issuer.issueAccessToken(payload, options);
  }

  generateReferenceToken(
    options?: ReferenceIssuanceOptions,
  ): SessionReferenceResult {
    return this.issuer.issueReferenceToken(options);
  }

  async generate(
    payload: TokenPayload,
    options?: GenerateOptions,
  ): Promise<TokenResult> {
    return this.issuer.issue(payload, options);
  }

  /** Epic 2: fail-shut JWT verification with standard claim checks. */
  async verify(token: string, options?: VerifyOptions): Promise<VerifyResult> {
    return this.verifier.verify(token, options);
  }

  /**
   * Exchange a valid refresh token for a new access/refresh pair (RTR).
   * Use from `POST /auth/refresh` — return `result.oauth` for RFC 6749 responses.
   */
  async rotate(
    refreshToken: string,
    options?: RotateOptions,
  ): Promise<RotateResult> {
    return this.rotator.rotate(refreshToken, options);
  }

  async terminate(session: SessionHandle): Promise<void> {
    return this.issuer.terminate(session);
  }

  async shutdown(): Promise<void> {
    // no-op until external stores are wired
  }
}
