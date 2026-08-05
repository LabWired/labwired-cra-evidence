# LabWired CRA-style secure-boot evidence pack

[![Evidence](https://github.com/w1ne/labwired-cra-evidence/actions/workflows/evidence.yml/badge.svg)](https://github.com/w1ne/labwired-cra-evidence/actions/workflows/evidence.yml)

**CI regenerates a downloadable evidence pack** for a virtual nRF52840 + ATECC608A
secure-boot / signed-OTA / anti-rollback lifecycle, running on the open
[LabWired](https://github.com/w1ne/labwired-core) simulator.

This is the same idea as keeping product demos and compliance packaging **out of
the engine repo** (similar to how [udslib](https://github.com/w1ne/udslib) is its
own stack, and demos like [labwired-nokia-ci-demo](https://github.com/w1ne/labwired-nokia-ci-demo)
live outside `labwired-core`).

## What you get

Every green CI run uploads a **`cra-evidence-pack`** artifact:

| File | Purpose |
|------|---------|
| `claims.json` / `claims.md` | Annex I–style claim rows → pass/fail + UART evidence |
| `run-manifest.json` | Signable SHA-256 digest of inputs + results |
| `result.json`, `uart.log`, `junit.xml` | Raw LabWired test outputs |
| `oem-verify-pubkey.hex` | OEM **public** verify key used this run |
| `README.md`, `limitations.md` | Honesty about sim gaps |

The OEM **private** signing key is **ephemeral** (generated in CI, discarded).
It is never committed here or in labwired-core.

## What this is not

- Not a Notified Body certificate  
- Not a full CRA technical file (no SBOM process, vuln handling, support period)  
- Not silicon / HIL — see pack `limitations.md`  

## Run locally

```bash
# needs: rustup, cargo, openssl, python3
./scripts/run_evidence.sh
# → out/cra-evidence-pack/
```

By default the script clones [labwired-core](https://github.com/w1ne/labwired-core)
at the pin in `LABWIRED_CORE_REF`. Override:

```bash
export LABWIRED_CORE_DIR=/path/to/labwired-core
./scripts/run_evidence.sh
```

## How it works

1. Build `firmware-nrf52840-secure-boot` from labwired-core  
2. `make_packages.py --ephemeral` → signed OTA packages + public key  
3. Patch lab `system.yaml` with `oem_pubkey_hex`  
4. `labwired-cli test` (45 assertions, three boots)  
5. Assemble `cra-evidence-pack/`  

Lab definition (system, firmware, smoke assertions) stays in
`labwired-core/examples/nrf52840-secure-boot-lab/`. This repo owns **evidence
packaging + CI only**.

## Blog / playground

Marketing embed: [CRA secure-boot post](https://labwired.com/blog/cra-secure-boot-ota-evidence-in-ci)
and the playground board `nrf52840-secure-boot-lab`.

## License

MIT — see [LICENSE](LICENSE).
