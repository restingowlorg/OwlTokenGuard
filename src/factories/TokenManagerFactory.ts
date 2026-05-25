import { TokenManager } from "../core/TokenManager";
import type { TokenConfig } from "../config/types";

/** Composition root (mirrors createRateLimiter). Always use this entry point. */
export function createTokenManager(config: TokenConfig): TokenManager {
  return TokenManager.create(config);
}
