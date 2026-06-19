import { createTokenManager } from "../src/factories/TokenManagerFactory";
import { TokenGenerationError } from "../src/errors/TokenGenerationError";
import { TEST_HMAC_SECRET } from "./helpers/keys";

describe("session termination", () => {
  const createManager = (
    onSessionTerminate?: (jti: string) => Promise<void>,
  ) => {
    const terminated: string[] = [];
    const manager = createTokenManager({
      expiresInSeconds: 3600,
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      onSessionTerminate: async ({ jti }) => {
        terminated.push(jti);
        await onSessionTerminate?.(jti);
      },
    });
    return { manager, terminated };
  };

  it("should terminate by jti handle", async () => {
    const { manager, terminated } = createManager();
    const first = await manager.generate({ sub: "user-123" });

    await manager.terminate({ jti: first.claims.jti });

    expect(terminated).toEqual([first.claims.jti]);
  });

  it("should terminate by StandardClaims handle", async () => {
    const { manager, terminated } = createManager();
    const first = await manager.generate({ sub: "user-123" });

    await manager.terminate(first.claims);

    expect(terminated).toEqual([first.claims.jti]);
  });

  it("should rotate sessions via previousSession on generate", async () => {
    const { manager, terminated } = createManager();

    const first = await manager.generate({ sub: "user-123" });
    const second = await manager.generate(
      { sub: "user-123" },
      { previousSession: first.claims },
    );

    expect(terminated).toContain(first.claims.jti);
    expect(second.claims.jti).not.toBe(first.claims.jti);
    expect(second.token).not.toBe(first.token);
  });

  it("should rotate using previousSession with jti-only handle", async () => {
    const { manager, terminated } = createManager();

    const first = await manager.generate({ sub: "user-456" });
    await manager.generate(
      { sub: "user-456" },
      { previousSession: { jti: first.claims.jti } },
    );

    expect(terminated).toContain(first.claims.jti);
  });

  it("should reject session handles without jti", async () => {
    const { manager } = createManager();

    await expect(
      manager.terminate({ jti: "" } as { jti: string }),
    ).rejects.toThrow(TokenGenerationError);
  });

  it("should no-op when onSessionTerminate is not configured", async () => {
    const manager = createTokenManager({
      expiresInSeconds: 3600,
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
    });
    const first = await manager.generate({ sub: "user-789" });

    await expect(manager.terminate(first.claims)).resolves.toBeUndefined();
  });

  it("should pass invalidateBefore to onSessionTerminate for cutoff policies", async () => {
    const cutoffs: Array<{ sub?: string; invalidateBefore?: number }> = [];
    const manager = createTokenManager({
      expiresInSeconds: 3600,
      algorithm: "HS256",
      hmacSecret: TEST_HMAC_SECRET,
      onSessionTerminate: async (context) => {
        cutoffs.push({
          sub: context.sub,
          invalidateBefore: context.invalidateBefore,
        });
      },
    });

    const issued = await manager.generateAccessToken({ sub: "user-cutoff" });
    const cutoff = Math.floor(Date.now() / 1000);

    await manager.terminate(issued.claims, {
      sub: "user-cutoff",
      invalidateBefore: cutoff,
    });

    expect(cutoffs).toEqual([
      {
        sub: "user-cutoff",
        invalidateBefore: cutoff,
      },
    ]);
  });
});
