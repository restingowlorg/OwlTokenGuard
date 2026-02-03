export interface CryptoOptions {
  /**
   * Optional master key (32 bytes).
   * If not provided, a random in-memory key is generated.
   */
  masterKey?: Buffer;
}
