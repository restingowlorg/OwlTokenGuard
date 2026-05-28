import { BaseError } from "./BaseError";

/** Story 2.2: token references keys from an unauthorized jku/x5u origin. */
export class UntrustedKeySourceError extends BaseError {
  constructor(message: string) {
    super("UNTRUSTED_KEY_SOURCE_ERROR", message);
  }
}
