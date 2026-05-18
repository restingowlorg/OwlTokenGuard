/**
 * A high-entropy bearer value returned to clients (sessions, refresh tokens, API secrets).
 */
export class OpaqueToken {
  readonly value: Buffer;

  constructor(value: Buffer) {
    this.value = value;
  }
}
