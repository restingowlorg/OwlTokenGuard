import { BaseCryptoError } from "./BaseCryptoError";

export class InsecureUsageError extends BaseCryptoError {
  readonly code = "CRYPTO_INSECURE_USAGE";

  constructor(message = "Insecure cryptographic usage detected") {
    super(message);
  }
}
