import { BaseError } from "./BaseError";

/** Story 2.x: fail-shut token verification failure. */
export class TokenVerificationError extends BaseError {
  constructor(message: string) {
    super("TOKEN_VERIFICATION_ERROR", message);
  }
}
