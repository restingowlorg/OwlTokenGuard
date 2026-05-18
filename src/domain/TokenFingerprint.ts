/**
 * What you persist instead of storing the plaintext opaque token verbatim.
 */
export class TokenFingerprint {
  readonly digest: Buffer;

  constructor(digest: Buffer) {
    this.digest = digest;
  }
}
