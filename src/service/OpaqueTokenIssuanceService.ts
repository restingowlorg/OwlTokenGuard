import { OpaqueToken } from "../domain/OpaqueToken";
import { NodeTokenAdapter } from "../infra/node/NodeTokenAdapter";

export class OpaqueTokenIssuanceService {
  constructor(
    private readonly adapter: NodeTokenAdapter,
    private readonly opaqueByteLength: number
  ) {}

  issue(): OpaqueToken {
    return new OpaqueToken(this.adapter.secureRandom(this.opaqueByteLength));
  }
}
