import type { PayloadCipher } from "./PayloadCipher";
import type { EncryptedPayload } from "./types";

/** Story 1.3: AES-256-GCM implementation of PayloadCipher. */
export class Aes256GcmCipher implements PayloadCipher {
  constructor(_encryptionKey: Buffer) {}

  async encrypt(_plaintext: string): Promise<EncryptedPayload> {
    // TODO: Story 1.3
    throw new Error("Not implemented");
  }

  async decrypt(_encrypted: EncryptedPayload): Promise<string> {
    // TODO: Story 1.3
    throw new Error("Not implemented");
  }
}
