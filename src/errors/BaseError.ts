/** Base error for all token-management failures. */
export class BaseError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}
