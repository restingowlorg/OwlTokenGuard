import { HashValue } from "../domain/HashValue";
import { InsecureUsageError } from "../errors/InsecureUsageError";
import { NodeCryptoAdapter } from "../infra/node/NodeCryptoAdapter";

export class HashingService {
  constructor(private readonly adapter: NodeCryptoAdapter) {}

  hash(data: Buffer): HashValue {
    if (!data || data.length === 0) {
      throw new InsecureUsageError("Cannot hash empty data");
    }

    return this.adapter.hash(data);
  }

  verify(data: Buffer, hash: HashValue): boolean {
    return this.adapter.verifyHash(data, hash);
  }
}
