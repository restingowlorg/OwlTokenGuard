import { BaseTokenError } from "./BaseTokenError";

export class InsecureTokenConfigurationError extends BaseTokenError {
  readonly code = "TOKEN_INSECURE_CONFIGURATION";

  constructor(message = "Insecure token library configuration", cause?: unknown) {
    super(message, cause);
  }
}
