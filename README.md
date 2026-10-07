# eth_proof_verifier

Verify [EIP-8025](https://eips.ethereum.org/EIPS/eip-8025) execution proofs. One binary, no setup, ~30 ms per proof.

```sh
cargo install --locked --git https://github.com/dapplion/eth_proof_verifier   # or a release binary
eth_proof_verifier --listen-address 127.0.0.1:8025
```

Lighthouse: `--proof-engine-endpoint http://127.0.0.1:8025`, once its client sends the four public-input fields the current spec defines.

## API

- `POST /v1/execution_proof_verifications` — query `proof_type`, `new_payload_request_root`, `successful_validation`, `chain_id`, `schema_id`; body the proof. `{"status":"VALID"}`, or `INVALID` with a reason. An unknown `proof_type` is `400`, never `INVALID`.
- `GET /v1/proof_types` — for the ENR `eproof` field and `ExecutionProofStatus`.

## Proof types

Immutable `(system, guest, version)` triples. `--proof-types FILE` adds more.

| # | guest | built with |
| --- | --- | --- |
| 1 | reth 0.1.0-rc.3 | SP1 6.4.0 |
| 2 | ethrex 27.0.0 | SP1 6.4.0 |
| 3 | reth 0.1.0-rc.4 | ZisK 1.2.0-alpha |
| 4 | ethrex 29.0.0 | ZisK 1.2.0-alpha |

## Adding a proving system

PRs welcome: implement `ProofVerifier::verify`, add a row. See `src/backend/sp1.rs` or `src/backend/zisk.rs`, ~130 lines each. Bring a crates.io verifier at a pinned version, a published verifying key per guest, and a real proof as a fixture. OpenVM waits on exactly that.

Apache-2.0 OR MIT. Guests, keys and fixture from [ere](https://github.com/eth-act/ere).
