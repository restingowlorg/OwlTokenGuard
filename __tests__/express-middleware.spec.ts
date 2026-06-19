import express, { type Express, type Request, type Response } from "express";
import request from "supertest";
import { createTokenManager } from "../src/factories/TokenManagerFactory";
import {
  expressVerifyToken,
  validateTokenMiddleware,
} from "../src/middlewares/express";
import { TEST_HMAC_SECRET } from "./helpers/keys";
import { buildSignedTestJwt } from "./helpers/jwt";

const managerConfig = {
  algorithm: "HS256" as const,
  hmacSecret: TEST_HMAC_SECRET,
  expiresInSeconds: 3600,
  allowedAlgorithms: ["HS256" as const],
};

function createTestApp(
  mountPath: string,
  middleware: ReturnType<typeof expressVerifyToken>,
): Express {
  const app = express();
  app.use(express.json());

  app.get("/public", (_req: Request, res: Response) => {
    res.json({ ok: true });
  });

  app.use(mountPath, middleware);

  app.get(`${mountPath}/profile`, (req: Request, res: Response) => {
    res.status(200).json({
      sub: req.auth?.payload.sub,
      jti: req.auth?.jti,
    });
  });

  return app;
}

describe("expressVerifyToken middleware", () => {
  const manager = createTokenManager(managerConfig);
  const auth = expressVerifyToken(manager, { purpose: "access" });
  const app = createTestApp("/api", auth);

  it("should allow public routes without a token", async () => {
    const response = await request(app).get("/public").expect(200);
    expect(response.body).toEqual({ ok: true });
  });

  it("should return 401 when Authorization header is missing", async () => {
    const response = await request(app).get("/api/profile").expect(401);
    expect(response.body.error).toBe("Unauthorized");
    expect(response.body.message).toMatch(/authorization header/i);
  });

  it("should return 401 when Bearer token is invalid", async () => {
    const response = await request(app)
      .get("/api/profile")
      .set("Authorization", "Bearer not-a-valid-jwt")
      .expect(401);

    expect(response.body.error).toBe("Unauthorized");
  });

  it("should return 401 when token signature is tampered", async () => {
    const issued = await manager.generateAccessToken({ sub: "user-1" });
    const tampered = `${issued.token.slice(0, -1)}x`;

    const response = await request(app)
      .get("/api/profile")
      .set("Authorization", `Bearer ${tampered}`)
      .expect(401);

    expect(response.body.error).toBe("Unauthorized");
  });

  it("should return 401 when token is expired", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expired = buildSignedTestJwt(managerConfig, {
      sub: "user-1",
      exp: now - 60,
    });

    const response = await request(app)
      .get("/api/profile")
      .set("Authorization", `Bearer ${expired}`)
      .expect(401);

    expect(response.body.message).toMatch(/expired/i);
  });

  it("should allow protected routes with a valid Bearer token", async () => {
    const issued = await manager.generateAccessToken({ sub: "user-42" });

    const response = await request(app)
      .get("/api/profile")
      .set("Authorization", `Bearer ${issued.token}`)
      .expect(200);

    expect(response.body).toEqual({
      sub: "user-42",
      jti: issued.claims.jti,
    });
  });

  it("should support validateTokenMiddleware alias", async () => {
    const aliasApp = createTestApp("/secure", validateTokenMiddleware(manager));
    const issued = await manager.generateAccessToken({ sub: "alias-user" });

    const response = await request(aliasApp)
      .get("/secure/profile")
      .set("Authorization", `Bearer ${issued.token}`)
      .expect(200);

    expect(response.body.sub).toBe("alias-user");
  });

  describe("onVerified control flow", () => {
    it("should run onVerified before the route and continue when next is called", async () => {
      const seen: string[] = [];
      const hookApp = createTestApp(
        "/hook-pass",
        expressVerifyToken(manager, {
          purpose: "access",
          onVerified: (result, next) => {
            seen.push(result.jti);
            next();
          },
        }),
      );
      const issued = await manager.generateAccessToken({
        sub: "hook-pass-user",
      });

      const response = await request(hookApp)
        .get("/hook-pass/profile")
        .set("Authorization", `Bearer ${issued.token}`)
        .expect(200);

      expect(seen).toEqual([issued.claims.jti]);
      expect(response.body).toEqual({
        sub: "hook-pass-user",
        jti: issued.claims.jti,
      });
    });

    it("should auto-advance when onVerified returns without calling next", async () => {
      const hookApp = createTestApp(
        "/hook-auto-next",
        expressVerifyToken(manager, {
          purpose: "access",
          onVerified: (result) => {
            expect(result.payload.sub).toBe("auto-next-user");
          },
        }),
      );
      const issued = await manager.generateAccessToken({
        sub: "auto-next-user",
      });

      const response = await request(hookApp)
        .get("/hook-auto-next/profile")
        .set("Authorization", `Bearer ${issued.token}`)
        .expect(200);

      expect(response.body.sub).toBe("auto-next-user");
    });

    it("should stop the chain when onVerified sends a response without calling next", async () => {
      const seen: string[] = [];
      const hookApp = createTestApp(
        "/hook-fail",
        expressVerifyToken(manager, {
          purpose: "access",
          onVerified: (result, _next, _req, res) => {
            seen.push(result.jti);
            res.status(401).json({
              error: "Unauthorized",
              message: "Blocked by onVerified",
            });
          },
        }),
      );
      const issued = await manager.generateAccessToken({
        sub: "hook-fail-user",
      });

      const response = await request(hookApp)
        .get("/hook-fail/profile")
        .set("Authorization", `Bearer ${issued.token}`)
        .expect(401);

      expect(seen).toEqual([issued.claims.jti]);
      expect(response.body.message).toBe("Blocked by onVerified");
    });

    it("should not auto-advance when onVerified sends a forbidden response", async () => {
      const hookApp = createTestApp(
        "/hook-forbidden",
        expressVerifyToken(manager, {
          purpose: "access",
          onVerified: (_result, _next, _req, res) => {
            res.status(403).json({ error: "Forbidden" });
          },
        }),
      );
      const issued = await manager.generateAccessToken({ sub: "denied-user" });

      const response = await request(hookApp)
        .get("/hook-forbidden/profile")
        .set("Authorization", `Bearer ${issued.token}`)
        .expect(403);

      expect(response.body.error).toBe("Forbidden");
    });
  });

  it("should support custom token extraction", async () => {
    const customApp = express();
    customApp.use(
      "/custom",
      expressVerifyToken(manager, {
        extractToken: (req) =>
          typeof req.headers["x-access-token"] === "string"
            ? req.headers["x-access-token"]
            : undefined,
      }),
    );
    customApp.get("/custom/profile", (req, res) => {
      res.json({ sub: req.auth?.payload.sub });
    });

    const issued = await manager.generateAccessToken({ sub: "custom-user" });

    await request(customApp).get("/custom/profile").expect(401);

    const response = await request(customApp)
      .get("/custom/profile")
      .set("x-access-token", issued.token)
      .expect(200);

    expect(response.body.sub).toBe("custom-user");
  });
});
