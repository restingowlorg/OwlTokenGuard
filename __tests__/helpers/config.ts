import type { TokenConfig } from "../../src/config/types";

/** No-op session terminate hook for tests that do not exercise revocation. */
export const noopOnSessionTerminate: TokenConfig["onSessionTerminate"] =
  async () => {};

/** Required TokenConfig hooks shared across test suites. */
export const requiredTestHooks = {
  onSessionTerminate: noopOnSessionTerminate,
} satisfies Pick<TokenConfig, "onSessionTerminate">;
