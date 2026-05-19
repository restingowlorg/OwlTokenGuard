/**
 * Story 1.1: HMAC secret length and entropy validation.
 */
export class SecretValidator {
  static validateHmacSecret(_secret: string): void {
    // TODO: Story 1.1 — minimum 64 characters
  }

  static assertHighEntropy(_secret: string): void {
    // TODO: Story 1.1 — reject predictable / low-entropy strings
  }
}
