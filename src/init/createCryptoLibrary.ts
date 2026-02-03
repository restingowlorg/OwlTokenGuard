import crypto from "crypto";
import { CryptoManager } from "../manager/CryptoManager";
import { NodeCryptoAdapter } from "../infra/node/NodeCryptoAdapter";
import { EncryptionService } from "../service/EncryptionService";
import { HashingService } from "../service/HashingService";
import { CryptoOptions } from "../types";
import { InsecureConfigurationError } from "../errors/InsecureConfigurationError";
import { DEFAULTS } from "../configs/defaults";

export function createCryptoLibrary(
  options?: CryptoOptions
): CryptoManager {
  const key =
    options?.masterKey ?? crypto.randomBytes(DEFAULTS.KEY_LENGTH);

  if (key.length !== DEFAULTS.KEY_LENGTH) {
    throw new InsecureConfigurationError(
      "Master key must be 32 bytes (256-bit)"
    );
  }

  const adapter = new NodeCryptoAdapter(key);

  const encryption = new EncryptionService(adapter);
  const hashing = new HashingService(adapter);

  return new CryptoManager(encryption, hashing);
}
