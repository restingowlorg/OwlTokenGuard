import { SecurityConfigurationError } from "../errors/SecurityConfigurationError";

/**
 * Story 1.1: detect predictable or low-entropy signing secrets.
 */
export class EntropyValidator {
  static assertHighEntropy(_value: string): void {
    // TODO: Story 1.1
    throw new SecurityConfigurationError("Not implemented");
  }
}
