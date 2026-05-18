import { BaseTokenError } from "./BaseTokenError";

export class InsecureTokenUsageError extends BaseTokenError {
  readonly code = "TOKEN_INSECURE_USAGE";

  constructor(message = "Token usage rejected", cause?: unknown) {
    super(message, cause);
  }
}
