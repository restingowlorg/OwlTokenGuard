import crypto, { CipherGCM, DecipherGCM } from "crypto";
import { DEFAULTS } from "../../configs/defaults";
import { CipherText } from "../../domain/CipherText";
import { HashValue } from "../../domain/HashValue";

export class NodeCryptoAdapter {
  private readonly key: Buffer;

  constructor(masterKey: Buffer) {
    this.key = masterKey;
  }

  encrypt(data: Buffer): CipherText {
    const iv = crypto.randomBytes(DEFAULTS.IV_LENGTH);

    const cipher = crypto.createCipheriv(
      DEFAULTS.ENCRYPTION_ALGORITHM,
      this.key,
      iv
    ) as CipherGCM; // 👈 explicit

    const encrypted = Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);

    const authTag = cipher.getAuthTag();

    return new CipherText(encrypted, iv, authTag);
  }

  decrypt(cipherText: CipherText): Buffer {
    const decipher = crypto.createDecipheriv(
      DEFAULTS.ENCRYPTION_ALGORITHM,
      this.key,
      cipherText.iv
    ) as DecipherGCM; // 👈 explicit

    decipher.setAuthTag(cipherText.authTag);

    return Buffer.concat([
      decipher.update(cipherText.value),
      decipher.final()
    ]);
  }

  hash(data: Buffer): HashValue {
    const salt = crypto.randomBytes(16);

    const hash = crypto.pbkdf2Sync(
      data,
      salt,
      DEFAULTS.HASH_ITERATIONS,
      DEFAULTS.HASH_KEY_LENGTH,
      DEFAULTS.HASH_DIGEST
    );

    return new HashValue(hash, salt);
  }

  verifyHash(data: Buffer, hash: HashValue): boolean {
    const recalculated = crypto.pbkdf2Sync(
      data,
      hash.salt,
      DEFAULTS.HASH_ITERATIONS,
      DEFAULTS.HASH_KEY_LENGTH,
      DEFAULTS.HASH_DIGEST
    );

    return crypto.timingSafeEqual(recalculated, hash.value);
  }
}
