import { TokenIssuer } from "./TokenIssuer";
import type { TokenConfig } from "../config/types";
import { validateConfig } from "../config/validation";
import type {
  TokenPayload,
  GenerateOptions,
  TokenResult,
  SessionHandle,
} from "./types";

/**
 * Story 1.3: unified API — tokenManager.generate(payload, options).
 * Instantiate only via {@link createTokenManager} or {@link TokenManager.create}.
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
