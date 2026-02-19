import { CipherText } from "../../src/domain/CipherText";
import { HashValue } from "../../src/domain/HashValue";
import { CryptoManager } from "../../src/manager/CryptoManager";
import { EncryptionService } from "../../src/service/EncryptionService";
import { HashingService } from "../../src/service/HashingService";

describe("CryptoManager", () => {
  const mockEncryption = {
    encrypt: jest.fn(),
    decrypt: jest.fn(),
  } as unknown as EncryptionService;

  const mockHashing = {
    hash: jest.fn(),
    verify: jest.fn(),
  } as unknown as HashingService;

  const manager = new CryptoManager(mockEncryption, mockHashing);

  const sampleData = Buffer.from("hello");
  const cipher = new CipherText(
    Buffer.from("x"),
    Buffer.from("y"),
    Buffer.from("z"),
  );
  const hash = new HashValue(Buffer.from("h"), Buffer.from("s"));

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("encrypt delegates to EncryptionService", () => {
    mockEncryption.encrypt = jest.fn().mockReturnValue(cipher);
    const result = manager.encrypt(sampleData);
    expect(result).toBe(cipher);
    expect(mockEncryption.encrypt).toHaveBeenCalledWith(sampleData);
  });

  it("decrypt delegates to EncryptionService", () => {
    mockEncryption.decrypt = jest.fn().mockReturnValue(sampleData);
    const result = manager.decrypt(cipher);
    expect(result).toBe(sampleData);
    expect(mockEncryption.decrypt).toHaveBeenCalledWith(cipher);
  });

  it("hash delegates to HashingService", () => {
    mockHashing.hash = jest.fn().mockReturnValue(hash);
    const result = manager.hash(sampleData);
    expect(result).toBe(hash);
    expect(mockHashing.hash).toHaveBeenCalledWith(sampleData);
  });

  it("verifyHash delegates to HashingService", () => {
    mockHashing.verify = jest.fn().mockReturnValue(true);
    const result = manager.verifyHash(sampleData, hash);
    expect(result).toBe(true);
    expect(mockHashing.verify).toHaveBeenCalledWith(sampleData, hash);
  });
});
