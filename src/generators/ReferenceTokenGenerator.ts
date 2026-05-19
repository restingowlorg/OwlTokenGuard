import type {
  ReferenceTokenOptions,
  ReferenceTokenResult,
} from "./types";

/**
 * Story 1.2: high-entropy opaque identifiers via crypto.randomBytes.
 * Non-sequential; suitable for backend-stored sessions.
 */
export class ReferenceTokenGenerator {
  generate(_options?: ReferenceTokenOptions): ReferenceTokenResult {
    // TODO: Story 1.2
    throw new Error("Not implemented");
  }
}
