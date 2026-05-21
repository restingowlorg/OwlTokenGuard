import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import type { PayloadCipher } from "./PayloadCipher";
import type { EncryptedPayload } from "./types";
import { TokenGenerationError } from "../errors/TokenGenerationError";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const KEY_LENGTH = 32;

/** Story 1.3: AES-256-GCM implementation of PayloadCipher. */
export class Aes256GcmCipher implements PayloadCipher {
  private readonly key: Buffer;

  constructor(encryptionKey: Buffer | string) {
    this.key =
      typeof encryptionKey === "string"
        ? Buffer.from(encryptionKey, "utf8")
        : encryptionKey;

    if (this.key.length !== KEY_LENGTH) {
      throw new TokenGenerationError(
        `AES-256-GCM requires a ${KEY_LENGTH}-byte encryption key`,
      );
    }
  }

  async encrypt(plaintext: string): Promise<EncryptedPayload> {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    return {
      ciphertext: ciphertext.toString("base64url"),
      iv: iv.toString("base64url"),
      authTag: authTag.toString("base64url"),
    };
  }

  async decrypt(encrypted: EncryptedPayload): Promise<string> {
    const iv = Buffer.from(encrypted.iv, "base64url");
    const authTag = Buffer.from(encrypted.authTag, "base64url");
    const ciphertext = Buffer.from(encrypted.ciphertext, "base64url");

    const decipher = createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString("utf8");
  }
}
