import { CipherText } from "../domain/CipherText";
import { InsecureUsageError } from "../errors/InsecureUsageError";
import { NodeCryptoAdapter } from "../infra/node/NodeCryptoAdapter";

export class EncryptionService {
  constructor(private readonly adapter: NodeCryptoAdapter) {}

  encrypt(data: Buffer): CipherText {
    if (!data || data.length === 0) {
      throw new InsecureUsageError("Cannot encrypt empty data");
    }

    return this.adapter.encrypt(data);
  }

  decrypt(cipher: CipherText): Buffer {
    return this.adapter.decrypt(cipher);
  }
}
