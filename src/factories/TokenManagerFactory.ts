import { TokenManager } from "../core/TokenManager";
import type { TokenConfig } from "../config/types";
import { validateConfig } from "../config/validation";

/** Composition root (mirrors createRateLimiter). */
export function createTokenManager(
  config: TokenConfig = {},
): TokenManager {
  validateConfig(config);
  return new TokenManager(config);
}
