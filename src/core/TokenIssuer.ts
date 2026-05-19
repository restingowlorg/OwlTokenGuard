import type { TokenConfig } from "../config/types";
import type { TokenPayload, GenerateOptions, TokenResult } from "./types";

/**
 * Story 1.3: hardened issuance orchestration.
 * - New session token per auth / re-auth
 * - Optional payload ciphering before signing
 * - Auto iat, nbf, jti claims
 */
export class TokenIssuer {
  constructor(private readonly _config: TokenConfig) {}

  async issue(
    _payload: TokenPayload,
    _options?: GenerateOptions,
  ): Promise<TokenResult> {
    throw new Error("Not implemented");
  }

  async terminate(_token: string): Promise<void> {
    throw new Error("Not implemented");
  }
}
