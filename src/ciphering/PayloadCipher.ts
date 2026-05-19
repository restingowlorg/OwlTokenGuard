import type { EncryptedPayload } from "./types";

/**
 * Story 1.3: encrypt JWT payload before signing (AES-256-GCM).
 * Ciphertext must include auth tags to prevent metadata tampering.
 */
export interface PayloadCipher {
  encrypt(plaintext: string): Promise<EncryptedPayload>;
  decrypt(encrypted: EncryptedPayload): Promise<string>;
}
