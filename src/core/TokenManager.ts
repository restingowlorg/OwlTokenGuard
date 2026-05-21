import { TokenIssuer } from "./TokenIssuer";
import type { TokenConfig } from "../config/types";
import type { TokenPayload, GenerateOptions, TokenResult } from "./types";

/**
 * Story 1.3: unified API — tokenManager.generate(payload, options).
 */
export class TokenManager {
  private readonly issuer: TokenIssuer;

  constructor(
    public readonly config: TokenConfig,
    dependencies?: { issuer?: TokenIssuer },
  ) {
    this.issuer = dependencies?.issuer ?? new TokenIssuer(config);
  }

  async generate(
    payload: TokenPayload,
    options?: GenerateOptions,
  ): Promise<TokenResult> {
    return this.issuer.issue(payload, options);
  }

  async terminate(token: string): Promise<void> {
    return this.issuer.terminate(token);
  }

  async shutdown(): Promise<void> {
    // no-op until external stores are wired
  }
}
