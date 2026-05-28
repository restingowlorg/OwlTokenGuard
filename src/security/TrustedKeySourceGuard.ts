import { UntrustedKeySourceError } from "../errors/UntrustedKeySourceError";

const DYNAMIC_KEY_HEADERS = ["jku", "x5u"] as const;

/**
 * Story 2.2: reject dynamic key headers unless source is on the trusted allowlist.
 */
export class TrustedKeySourceGuard {
  static assertTrustedHeaders(
    header: Record<string, unknown>,
    trustedDomains: string[] = [],
  ): void {
    for (const name of DYNAMIC_KEY_HEADERS) {
      const value = header[name];
      if (value === undefined) continue;

      if (typeof value !== "string" || value.length === 0) {
        throw new UntrustedKeySourceError(`Invalid ${name} header value`);
      }

      if (trustedDomains.length === 0) {
        throw new UntrustedKeySourceError(
          `Token contains ${name} header but no trusted key source domains are configured`,
        );
      }

      TrustedKeySourceGuard.assertDomainAllowed(value, trustedDomains, name);
    }
  }

  private static assertDomainAllowed(
    urlValue: string,
    trustedDomains: string[],
    headerName: string,
  ): void {
    let hostname: string;
    try {
      hostname = new URL(urlValue).hostname.toLowerCase();
    } catch {
      throw new UntrustedKeySourceError(`Malformed ${headerName} URL`);
    }

    const allowed = trustedDomains.some((domain) => {
      const normalized = domain.toLowerCase();
      return hostname === normalized || hostname.endsWith(`.${normalized}`);
    });

    if (!allowed) {
      throw new UntrustedKeySourceError(
        `Untrusted ${headerName} key source: ${hostname}`,
      );
    }
  }
}
