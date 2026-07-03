/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["**/__tests__/**/*.spec.ts"],
  collectCoverageFrom: [
    "src/**/*.ts",
    "!src/index.ts",
    "!src/**/*.d.ts",
    "!src/**/types.ts",
    "!src/config/defaults.ts",
  ],
  coverageThreshold: {
    global: {
      statements: 80,
      branches: 70,
      functions: 80,
      lines: 80,
    },
    "src/core/**/*.ts": {
      statements: 85,
      branches: 75,
      functions: 80,
      lines: 85,
    },
    "src/jwt/**/*.ts": {
      statements: 80,
      branches: 65,
      functions: 85,
      lines: 80,
    },
    "src/security/**/*.ts": {
      statements: 75,
      branches: 70,
      functions: 75,
      lines: 75,
    },
    "src/ciphering/**/*.ts": {
      statements: 90,
      branches: 50,
      functions: 90,
      lines: 90,
    },
  },
  clearMocks: true,
  resetMocks: true,
  watchman: false,
};
