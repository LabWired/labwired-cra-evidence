#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build cra-evidence-pack/ from a labwired-cli test output directory."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

README = """# Secure-boot / OTA evidence pack (LabWired virtual run)

This directory is a **CI evidence pack** from the nRF52840 secure-boot lab
running on the [LabWired](https://github.com/w1ne/labwired-core) simulator.

## What it is

- A **repeatable** demonstration of OTP root key provision, AES boot challenge,
  ECDSA-signed OTA (accept + forge reject), anti-rollback, SE attestation, and
  NV commit — asserted in sim and summarized in `claims.json`.
- `run-manifest.json` + `run-manifest.digest.sig`: digest of the run, signed
  with an **ephemeral pack-signing key** (public key only is retained).
- OEM OTA signing used an **ephemeral** private key; only `oem-verify-pubkey.hex`
  is retained.

## What it is not

- Not a Notified Body certificate or full CRA technical documentation.
- Not silicon / HIL — see `limitations.md`.
- Claim titles are **technical** (what was asserted), not legal findings.

Regenerate: https://github.com/w1ne/labwired-cra-evidence
"""

LIMITATIONS = """# Honest limitations

- On-chip and SE RNGs in the simulator are **deterministic PRNGs** (reproducible
  CI). They say nothing about entropy quality on real silicon.
- The “boot challenge” is AES-128-ECB of a fixed string vs a golden — not a full
  measured-boot / chain-of-trust implementation.
- `APPROTECT` is **stored**, not enforced — debug-port lockout side effects are
  not modelled.
- Flash follows 1→0 / erase semantics but not real erase/program timing.
- The SE implements authentic ATECC608A command *shape* with real ECDSA (p256
  crate), not the full datasheet (no wake/idle timing; fixed demo device key).
- Pack-signing key is ephemeral per CI run (demo of signature attachment, not
  a long-lived organizational signing identity).
- This pack does not cover SBOM, vulnerability handling, support period, or
  other product-lifecycle compliance obligations.
"""


def load_result(out_dir: Path) -> dict:
    p = out_dir / "result.json"
    if not p.is_file():
        return {}
    return json.loads(p.read_text())


def uart_text(out_dir: Path) -> str:
    p = out_dir / "uart.log"
    if p.is_file():
        return p.read_text(errors="replace")
    result = load_result(out_dir)
    for key in ("uart", "uart_log"):
        if isinstance(result.get(key), str):
            return result[key]
    return ""


def overall_status(result: dict) -> str:
    st = (result.get("status") or "").lower()
    if st in ("pass", "passed", "ok", "success"):
        return "pass"
    if st in ("fail", "failed", "error"):
        return "fail"
    assertions = result.get("assertions") or []
    if assertions and all(a.get("passed") for a in assertions):
        return "pass"
    if assertions:
        return "fail"
    return "unknown"


def _as_int(v) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 0)
    raise TypeError(type(v))


def memory_assertion_passed(result: dict, address, expected, size: int = 4) -> bool:
    """Match a memory_value assertion that already passed in result.json."""
    addr = _as_int(address)
    exp = _as_int(expected)
    for a in result.get("assertions") or []:
        if not a.get("passed"):
            continue
        mv = a.get("assertion", {}).get("memory_value")
        if not isinstance(mv, dict):
            continue
        if _as_int(mv.get("address")) != addr:
            continue
        if _as_int(mv.get("expected_value")) != exp:
            continue
        if int(mv.get("size") or 4) != int(size):
            continue
        return True
    return False


def eval_evidence(item: dict, *, out_dir: Path, uart: str, result: dict) -> bool:
    kind = item.get("kind")
    if kind == "uart_contains":
        return item["value"] in uart
    if kind == "file_present":
        return (out_dir / item["path"]).is_file() or (out_dir.parent / item["path"]).is_file()
    if kind == "manifest_digest_nonempty":
        man = out_dir / "run-manifest.json"
        if not man.is_file():
            return False
        dig = json.loads(man.read_text()).get("digest") or ""
        return len(dig) >= 32
    if kind == "memory_value":
        return memory_assertion_passed(
            result,
            item["address"],
            item["expected_value"],
            int(item.get("size") or 4),
        )
    if kind == "result_status_pass":
        return overall_status(result) == "pass"
    return False


def sign_manifest_digest(out_dir: Path, pack: Path) -> None:
    """Detach-sign run-manifest digest with an ephemeral pack-signing key."""
    man = out_dir / "run-manifest.json"
    if not man.is_file():
        return
    digest = json.loads(man.read_text()).get("digest") or ""
    if len(digest) < 32:
        return
    digest_file = pack / "run-manifest.digest"
    digest_file.write_text(digest + "\n")
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        key = td_path / "pack-sign.pem"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)],
            check=True,
            capture_output=True,
        )
        pub = pack / "pack-signing-pubkey.pem"
        subprocess.run(
            ["openssl", "ec", "-in", str(key), "-pubout", "-out", str(pub)],
            check=True,
            capture_output=True,
        )
        sig = pack / "run-manifest.digest.sig"
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(sig), str(digest_file)],
            check=True,
            capture_output=True,
        )
        # Verify immediately so a broken openssl doesn't ship a fake claim
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig), str(digest_file)],
            check=True,
            capture_output=True,
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--pack-dir", type=Path, required=True)
    ap.add_argument("--claims-map", type=Path, required=True)
    ap.add_argument("--pubkey-hex", type=Path, required=True)
    args = ap.parse_args()

    claims_doc = json.loads(args.claims_map.read_text())
    result = load_result(args.out_dir)
    uart = uart_text(args.out_dir)
    run_ok = overall_status(result) == "pass"

    pack = args.pack_dir
    pack.mkdir(parents=True, exist_ok=True)

    for name in ("result.json", "uart.log", "junit.xml", "run-manifest.json"):
        src = args.out_dir / name
        if src.is_file():
            shutil.copy2(src, pack / name)

    # Sign after copy so pack has digest files for claim eval
    sign_manifest_digest(args.out_dir, pack)
    # Copy sig artifacts into out_dir too so file_present checks on out_dir work
    for name in ("run-manifest.digest", "run-manifest.digest.sig", "pack-signing-pubkey.pem"):
        src = pack / name
        if src.is_file():
            shutil.copy2(src, args.out_dir / name)

    pubkey = args.pubkey_hex.read_text().strip()
    (pack / "oem-verify-pubkey.hex").write_text(pubkey + "\n")
    (pack / "README.md").write_text(README)
    (pack / "limitations.md").write_text(LIMITATIONS)

    evaluated = []
    any_fail = False
    for claim in claims_doc.get("claims", []):
        norm_ev = claim.get("evidence") or []
        # For signature files, check pack dir as well via out_dir copies above
        flags = [
            eval_evidence(e, out_dir=args.out_dir, uart=uart, result=result) for e in norm_ev
        ]
        ok = all(flags) if flags else False
        if not run_ok and claim["id"] not in ("run_manifest_present",):
            if any(e.get("kind") in ("uart_contains", "memory_value") for e in norm_ev):
                ok = False
        status = "pass" if ok else "fail"
        if status == "fail":
            any_fail = True
        evaluated.append(
            {
                "id": claim["id"],
                "title": claim.get("title"),
                "theme": claim.get("theme"),
                "status": status,
                "notes": claim.get("notes"),
                "evidence": norm_ev,
            }
        )

    pack_status = "fail" if any_fail or not run_ok else "pass"
    claims_out = {
        "schema_version": claims_doc.get("schema_version", "1.1"),
        "pack_status": pack_status,
        "run_status": overall_status(result),
        "claims": evaluated,
    }
    (pack / "claims.json").write_text(json.dumps(claims_out, indent=2) + "\n")

    md = [
        "# Claims",
        "",
        f"**Pack status:** `{pack_status}`",
        "",
        "Technical assertions only — not a legal CRA finding.",
        "",
        "| id | status | title |",
        "|----|--------|-------|",
    ]
    for c in evaluated:
        md.append(f"| `{c['id']}` | **{c['status']}** | {c['title']} |")
    md.append("")
    (pack / "claims.md").write_text("\n".join(md))

    print(f"wrote pack to {pack} status={pack_status}")
    return 0 if pack_status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
