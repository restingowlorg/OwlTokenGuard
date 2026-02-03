export class CipherText {
  readonly value: Buffer;
  readonly iv: Buffer;
  readonly authTag: Buffer;

  constructor(value: Buffer, iv: Buffer, authTag: Buffer) {
    this.value = value;
    this.iv = iv;
    this.authTag = authTag;
  }
}
