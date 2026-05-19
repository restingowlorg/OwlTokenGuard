import { SecurityConfigurationError } from "../errors/SecurityConfigurationError";

export type SigningAlgorithm =
  | "RS256"
  | "ES256"
  | "HS256"
  | "HS512";

const BLOCKED_ALGORITHMS = ["none"] as const;

/**
 * Story 1.1: blocks `none` and unauthorized hashing types.
 */
export class AlgorithmGuard {
  static assertAllowed(algorithm: string): asserts algorithm is SigningAlgorithm {
    if ((BLOCKED_ALGORITHMS as readonly string[]).includes(algorithm)) {
      throw new SecurityConfigurationError(
        `Algorithm "${algorithm}" is not permitted`,
      );
    }
    // TODO: Story 1.1 — reject unknown algorithms
  }

  /** Story 1.1: expose validateAlgorithm for key/algorithm pairing. */
  static validateAlgorithm(
    _algorithm: SigningAlgorithm,
    _keyMaterial: unknown,
  ): void {
    // TODO: Story 1.1
  }
}
