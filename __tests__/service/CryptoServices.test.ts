// __tests__/CryptoServices.test.ts

import { CipherText } from "../../src/domain/CipherText";
import { HashValue } from "../../src/domain/HashValue";
import { InsecureUsageError } from "../../src/errors/InsecureUsageError";
import { NodeCryptoAdapter } from "../../src/infra/node/NodeCryptoAdapter";
import { EncryptionService } from "../../src/service/EncryptionService";
import { HashingService } from "../../src/service/HashingService";

// Mock adapter for deterministic testing
class MockAdapter extends NodeCryptoAdapter {
  encrypt = jest.fn(
    (data: Buffer) =>
      new CipherText(
        Buffer.from("encrypted"),
        Buffer.from("iv"),
        Buffer.from("tag"),
      ),
  );
  decrypt = jest.fn((cipher: CipherText) => Buffer.from("decrypted"));
  hash = jest.fn(
    (data: Buffer) => new HashValue(Buffer.from("hash"), Buffer.from("salt")),
  );
  verifyHash = jest.fn((data: Buffer, hash: HashValue) => true);
}

describe("EncryptionService", () => {
  const adapter = new MockAdapter(Buffer.alloc(32));
  const service = new EncryptionService(adapter);

  it("encrypts data using adapter", () => {
    const data = Buffer.from("hello");
    const result = service.encrypt(data);
    expect(result.value.toString()).toBe("encrypted");
    expect(adapter.encrypt).toHaveBeenCalledWith(data);
  });

  it("throws error when encrypting empty data", () => {
    expect(() => service.encrypt(Buffer.from(""))).toThrow(InsecureUsageError);
  });

  it("decrypts data using adapter", () => {
    const cipher = new CipherText(
      Buffer.from("x"),
      Buffer.from("y"),
      Buffer.from("z"),
    );
    const result = service.decrypt(cipher);
    expect(result.toString()).toBe("decrypted");
    expect(adapter.decrypt).toHaveBeenCalledWith(cipher);
  });
});

describe("HashingService", () => {
  const adapter = new MockAdapter(Buffer.alloc(32));
  const service = new HashingService(adapter);

  it("hashes data using adapter", () => {
    const data = Buffer.from("hello");
    const hash = service.hash(data);
    expect(hash.value.toString()).toBe("hash");
    expect(adapter.hash).toHaveBeenCalledWith(data);
  });

  it("throws error when hashing empty data", () => {
    expect(() => service.hash(Buffer.from(""))).toThrow(InsecureUsageError);
  });

  it("verifies data using adapter", () => {
    const data = Buffer.from("hello");
    const hash = new HashValue(Buffer.from("x"), Buffer.from("y"));
    const result = service.verify(data, hash);
    expect(result).toBe(true);
    expect(adapter.verifyHash).toHaveBeenCalledWith(data, hash);
  });
});
