import { BaseError } from "./BaseError";

/** Thrown when token issuance fails at runtime. */
export class TokenGenerationError extends BaseError {
  constructor(message: string) {
    super("TOKEN_GENERATION_ERROR", message);
  }
}
