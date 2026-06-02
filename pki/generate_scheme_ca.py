#!/usr/bin/env python3
"""
generate_scheme_ca.py — Scheme Operator: one-time CA setup.

Generates:
  pki/scheme/root-ca.key          Scheme Root CA private key   (KEEP OFFLINE)
  pki/scheme/root-ca.pem          Scheme Root CA certificate   (distribute to all PISPs)
  pki/scheme/intermediate-ca.key  Intermediate CA private key  (protect carefully)
  pki/scheme/intermediate-ca.pem  Intermediate CA certificate  (distribute to all PISPs)

Run once when setting up the scheme.  The root key should be taken offline
immediately after this script completes.

Usage:
    python3 pki/generate_scheme_ca.py [--out-dir pki/scheme]
"""

import argparse
import sys
from pathlib import Path

# Allow running from repo root or from pki/ directory
sys.path.insert(0, str(Path(__file__).parent))
import pki as _pki


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default=str(Path(__file__).parent / "scheme"),
        help="Directory to write CA artefacts into (default: pki/scheme/)",
    )
    args = parser.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Check for existing CAs to avoid accidental overwrite
    if (out / "root-ca.pem").exists():
        print(f"ERROR: {out}/root-ca.pem already exists. Delete it first if you "
              "intend to regenerate the Scheme CA (this invalidates ALL PISP CAs).",
              file=sys.stderr)
        sys.exit(1)

    print("Generating Scheme Root CA...")
    root_key, root_cert = _pki.generate_root_ca()

    print("Generating Scheme Intermediate CA...")
    int_key, int_cert = _pki.generate_intermediate_ca(root_key, root_cert)

    # Write Root CA
    (out / "root-ca.key").write_bytes(_pki.key_to_pem(root_key))
    (out / "root-ca.pem").write_bytes(_pki.cert_to_pem(root_cert))

    # Write Intermediate CA
    (out / "intermediate-ca.key").write_bytes(_pki.key_to_pem(int_key))
    (out / "intermediate-ca.pem").write_bytes(_pki.cert_to_pem(int_cert))

    print(f"\nDone. Artefacts written to {out}/")
    print(f"  {out}/root-ca.pem          — distribute to all PISPs as trust anchor")
    print(f"  {out}/root-ca.key          — TAKE OFFLINE, store in secure location")
    print(f"  {out}/intermediate-ca.pem  — distribute to all PISPs")
    print(f"  {out}/intermediate-ca.key  — protect; used only for PISP onboarding")


if __name__ == "__main__":
    main()
