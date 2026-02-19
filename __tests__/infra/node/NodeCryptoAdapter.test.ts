// __tests__/NodeCryptoAdapter.test.ts
import crypto from "crypto";
import { DEFAULTS } from "../../../src/configs/defaults";
import { NodeCryptoAdapter } from "../../../src/infra/node/NodeCryptoAdapter";

describe("NodeCryptoAdapter", () => {
  const masterKey = crypto.randomBytes(DEFAULTS.KEY_LENGTH);
  const adapter = new NodeCryptoAdapter(masterKey);

  const sampleData = Buffer.from("Hello, world!");

  describe("encrypt & decrypt", () => {
    it("should decrypt encrypted data correctly", () => {
      const cipherText = adapter.encrypt(sampleData);
      const decrypted = adapter.decrypt(cipherText);
      expect(decrypted).toEqual(sampleData);
    });

    it("should produce different ciphertexts for same input due to random IV", () => {
      const cipher1 = adapter.encrypt(sampleData);
      const cipher2 = adapter.encrypt(sampleData);
      expect(cipher1.value.equals(cipher2.value)).toBe(false);
      expect(cipher1.iv.equals(cipher2.iv)).toBe(false);
    });
  });

  describe("hash & verifyHash", () => {
    it("should verify correct hash successfully", () => {
      const hash = adapter.hash(sampleData);
      const isValid = adapter.verifyHash(sampleData, hash);
      expect(isValid).toBe(true);
    });

    it("should fail verification for incorrect data", () => {
      const hash = adapter.hash(sampleData);
      const invalidData = Buffer.from("Wrong data");
      const isValid = adapter.verifyHash(invalidData, hash);
      expect(isValid).toBe(false);
    });

    it("should generate different hashes for same input due to random salt", () => {
      const hash1 = adapter.hash(sampleData);
      const hash2 = adapter.hash(sampleData);
      expect(hash1.value.equals(hash2.value)).toBe(false);
      expect(hash1.salt.equals(hash2.salt)).toBe(false);
    });
  });
});
