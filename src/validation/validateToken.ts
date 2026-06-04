import type { TokenManager } from "../core/TokenManager";
import type { VerifyOptions, VerifyResult } from "../validation/types";

/**
 * Core validation function — prefer this or {@link TokenManager.verify}.
 * Runs default fail-shut checks; extend with `options.onVerified` for custom logic.
 */
export async function validateToken(
  tokenManager: TokenManager,
  token: string,
  options?: VerifyOptions,
): Promise<VerifyResult> {
  return tokenManager.verify(token, options);
}
