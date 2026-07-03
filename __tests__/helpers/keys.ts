import { generateKeyPairSync } from "crypto";

/** 64+ character high-entropy secret for HS256/HS512 tests. */
export const TEST_HMAC_SECRET =
  "xK9#mP2$vL8@nQ4&wR7!zT1^yU5*bI0+cO3-dF6_eH9=gJ2~aS7%hD4&kF8#qW1!rE6@tY3";

export function generateRsaKeyPair(): {
  privateKey: string;
  publicKey: string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
  };
}

/** Intentionally weak 1024-bit RSA key pair for negative security tests. */
export function generateWeakRsaKeyPair(): {
  privateKey: string;
  publicKey: string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 1024,
  });
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
  };
}

export function generateEcKeyPair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
  };
}

/** Intentionally non-P-256 EC key pair for negative ES256 security tests. */
export function generateNonP256EcKeyPair(): {
  privateKey: string;
  publicKey: string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-384",
  });
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
  };
}
