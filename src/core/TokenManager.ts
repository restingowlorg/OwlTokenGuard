import { TokenIssuer } from "./TokenIssuer";
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
} from "./types";

/**
 * Token management API. Instantiate only via {@link createTokenManager}.
 */
export class TokenManager {
  private readonly issuer: TokenIssuer;

  private constructor(
    public readonly config: TokenConfig,
    dependencies?: { issuer?: TokenIssuer },
  ) {
    this.issuer = dependencies?.issuer ?? new TokenIssuer(config);
  }

  /** Validated construction — prefer `createTokenManager()` from the factory. */
  static create(
    config: TokenConfig,
    dependencies?: { issuer?: TokenIssuer },
  ): TokenManager {
    validateConfig(config);
    return new TokenManager(config, dependencies);
  }

  /** Issue a signed JWT access token only. */
  async generateAccessToken(
    payload: TokenPayload,
    options?: AccessTokenOptions,
  ): Promise<AccessTokenResult> {
    return this.issuer.issueAccessToken(payload, options);
  }

  /** Issue an opaque reference token only. */
  generateReferenceToken(
    options?: ReferenceIssuanceOptions,
  ): SessionReferenceResult {
    return this.issuer.issueReferenceToken(options);
  }

  /**
   * Compatibility wrapper: JWT + opaque reference token.
   * Prefer `generateAccessToken` or `generateReferenceToken` when only one is needed.
   */
  async generate(
    payload: TokenPayload,
    options?: GenerateOptions,
  ): Promise<TokenResult> {
    return this.issuer.issue(payload, options);
  }

  async terminate(session: SessionHandle): Promise<void> {
    return this.issuer.terminate(session);
  }

  async shutdown(): Promise<void> {
    // no-op until external stores are wired
  }
}
