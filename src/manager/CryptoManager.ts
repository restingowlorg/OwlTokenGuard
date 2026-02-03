import { EncryptionService } from "../service/EncryptionService";
import { HashingService } from "../service/HashingService";
import { CipherText } from "../domain/CipherText";
import { HashValue } from "../domain/HashValue";

export class CryptoManager {
  constructor(
    private readonly encryption: EncryptionService,
    private readonly hashing: HashingService
  ) {}

  encrypt(data: Buffer): CipherText {
    return this.encryption.encrypt(data);
  }

  decrypt(cipher: CipherText): Buffer {
    return this.encryption.decrypt(cipher);
  }

  hash(data: Buffer): HashValue {
    return this.hashing.hash(data);
  }

  verifyHash(data: Buffer, hash: HashValue): boolean {
    return this.hashing.verify(data, hash);
  }
}
