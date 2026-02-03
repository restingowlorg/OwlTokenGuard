export class HashValue {
  readonly value: Buffer;
  readonly salt: Buffer;

  constructor(value: Buffer, salt: Buffer) {
    this.value = value;
    this.salt = salt;
  }
}
