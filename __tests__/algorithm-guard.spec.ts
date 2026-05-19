import { AlgorithmGuard } from "../src/security/AlgorithmGuard";
import { SecurityConfigurationError } from "../src/errors/SecurityConfigurationError";

describe("AlgorithmGuard", () => {
  it("should reject the none algorithm", () => {
    expect(() => AlgorithmGuard.assertAllowed("none")).toThrow(
      SecurityConfigurationError,
    );
    expect(() => AlgorithmGuard.assertAllowed("none")).toThrow(
      /not permitted/i,
    );
  });

  it("should allow supported signing algorithms", () => {
    expect(() => AlgorithmGuard.assertAllowed("RS256")).not.toThrow();
    expect(() => AlgorithmGuard.assertAllowed("ES256")).not.toThrow();
    expect(() => AlgorithmGuard.assertAllowed("HS256")).not.toThrow();
    expect(() => AlgorithmGuard.assertAllowed("HS512")).not.toThrow();
  });
});
