import { BaseCryptoError } from "./BaseCryptoError";

export class InsecureConfigurationError extends BaseCryptoError {
  readonly code = "CRYPTO_INSECURE_CONFIGURATION";

  constructor(message = "Insecure cryptographic configuration") {
    super(message);
  }
}
