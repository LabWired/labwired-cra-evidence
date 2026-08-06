# LabWired secure-boot / OTA evidence pack (CI)

[![Evidence](https://github.com/LabWired/labwired-cra-evidence/actions/workflows/evidence.yml/badge.svg)](https://github.com/LabWired/labwired-cra-evidence/actions/workflows/evidence.yml)

**CI regenerates a downloadable evidence pack** for a virtual nRF52840 + ATECC608A
secure-boot / signed-OTA / anti-rollback lifecycle on the open
[LabWired](https://github.com/w1ne/labwired-core) simulator.

Packaging lives **here**, not in the engine repo (same idea as
[udslib](https://github.com/w1ne/udslib) and
[labwired-nokia-ci-demo](https://github.com/w1ne/labwired-nokia-ci-demo)).

## What you get

Every green Actions run uploads **`cra-evidence-pack`**:

| File | Purpose |
|------|---------|
| `claims.json` / `claims.md` | Technical claims bound to **UART + memory assertions** that passed |
| `run-manifest.json` | Reproducible digest of inputs + results |
| `run-manifest.digest` + `.sig` | Digest text + OpenSSL ECDSA detached signature |
| `pack-signing-pubkey.pem` | Public half of the ephemeral pack-signing key |
| `result.json`, `uart.log`, `junit.xml` | Raw LabWired outputs |
| `oem-verify-pubkey.hex` | OEM **public** OTA-verify key for this run |
| `limitations.md` | What the sim does not prove |

OEM OTA private key and pack-signing private key are **ephemeral** (generated
in CI, discarded). Never committed.

## What this is not

- Not a Notified Body certificate  
- Not a full CRA technical file (no SBOM process, vuln handling, support period)  
- Not silicon / HIL — see pack `limitations.md`  
- Claim titles describe **what was asserted in sim**, not legal Annex I findings  

## Run locally

```bash
# needs: rustup, cargo, openssl, python3
./scripts/run_evidence.sh
# → out/nrf52840-secure-boot-evidence/cra-evidence-pack/
```

Default: clones [labwired-core](https://github.com/w1ne/labwired-core) at
`LABWIRED_CORE_REF`. Override:

```bash
export LABWIRED_CORE_DIR=/path/to/labwired-core
./scripts/run_evidence.sh
```

## How it works

1. Build `firmware-nrf52840-secure-boot` from labwired-core  
2. `make_packages.py --ephemeral` → signed OTA packages + public key  
3. Patch lab `system.yaml` with `oem_pubkey_hex`  
4. `labwired-cli test` (45 assertions)  
5. Build pack + **sign the run-manifest digest** with an ephemeral pack key  

Lab definition (system, firmware, smoke) stays in
`labwired-core/examples/nrf52840-secure-boot-lab/`.

## Story

[Downloadable evidence pack in CI](https://labwired.com/blog/downloadable-cra-evidence-pack-in-ci) ·
[Three-boot lab walkthrough](https://labwired.com/blog/cra-secure-boot-ota-evidence-in-ci)

## License

MIT — see [LICENSE](LICENSE).
