import { BaseError } from "./BaseError";

/** Thrown when signing keys, algorithms, or entropy policy is invalid. */
export class SecurityConfigurationError extends BaseError {
  constructor(message: string) {
    super("SECURITY_CONFIGURATION_ERROR", message);
  }
}
