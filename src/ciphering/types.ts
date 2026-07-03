/** Story 1.3: AES-256-GCM ciphertext with authentication tag. */
export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  authTag: string;
}
