"""PR verification CLI for the Hiero Identity MVP.

Usage:
  - Generate a sample VC: `python pr_verify.py --generate-sample examples/sample_vc.json`
  - Verify a VC against an email: `python pr_verify.py --vc examples/sample_vc.json --email alice@example.com`
"""
import argparse
import json
import sys
import os
from src.mvp.keys import generate_keypair, pubkey_to_did
from src.mvp.vc import issue_vc, verify_vc, credential_subject_email


def generate_sample(path: str):
    issuer_priv, issuer_pub, issuer_priv_pem, issuer_pub_pem = generate_keypair()
    subj_priv, subj_pub, subj_priv_pem, subj_pub_pem = generate_keypair()
    subj_did = pubkey_to_did(subj_pub)
    email = "alice@example.com"
    vc = issue_vc(issuer_priv, issuer_pub_pem, subj_did, email)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vc, f, indent=2)
    print(f"Wrote sample VC to {path}")
    print(f"Subject DID: {subj_did}")
    return 0


def verify(vc_path: str, email: str) -> int:
    with open(vc_path, "r", encoding="utf-8") as f:
        vc = json.load(f)
    ok = verify_vc(vc)
    bound = credential_subject_email(vc)
    matched = (bound == email)
    result = {"signature_valid": ok, "email_bound": bound, "email_matches": matched}
    print(json.dumps(result, indent=2))
    return 0 if (ok and matched) else 2


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--generate-sample", dest="generate", help="Write a sample VC to this path")
    p.add_argument("--vc", help="Path to VC JSON file")
    p.add_argument("--email", help="Commit author email to verify against VC subject")
    args = p.parse_args()

    if args.generate:
        return generate_sample(args.generate)
    if args.vc and args.email:
        return verify(args.vc, args.email)
    p.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
