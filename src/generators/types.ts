/** Story 1.2: supported opaque token encodings (ASVS 7.2.3). */
export type ReferenceTokenEncoding = "uuidv4" | "base64url";

export interface ReferenceTokenOptions {
  encoding?: ReferenceTokenEncoding;
  /** Minimum 128 bits of entropy. */
  entropyBits?: number;
}

export interface ReferenceTokenResult {
  token: string;
  encoding: ReferenceTokenEncoding;
  entropyBits: number;
}
