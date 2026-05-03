"""Demo script for the Hiero Identity MVP.

Creates an issuer and contributor DID/keypair, issues a VC linking the contributor email,
verifies the VC, and simulates verifying a commit author against the VC.
"""
import sys
import json
from src.mvp.keys import generate_keypair, pubkey_to_did
from src.mvp.vc import issue_vc, verify_vc, credential_subject_email


def run_demo():
    # Generate issuer keys
    issuer_priv, issuer_pub, issuer_priv_pem, issuer_pub_pem = generate_keypair()
    issuer_did = pubkey_to_did(issuer_pub)
    print("Issuer DID:", issuer_did)

    # Generate contributor keys
    subj_priv, subj_pub, subj_priv_pem, subj_pub_pem = generate_keypair()
    subj_did = pubkey_to_did(subj_pub)
    contributor_email = "alice@example.com"
    print("Contributor DID:", subj_did)
    print("Contributor email:", contributor_email)

    # Issue VC
    vc = issue_vc(issuer_priv, issuer_pub_pem, subj_did, contributor_email)
    print("\nIssued VC:\n", json.dumps(vc, indent=2))

    # Verify VC
    ok = verify_vc(vc)
    print("\nVC signature valid:", ok)

    # Simulate verifying a commit author email against the VC
    commit_author_email = "alice@example.com"
    bound_email = credential_subject_email(vc)
    verified_author = ok and (commit_author_email == bound_email)
    print("Commit author email matches VC subject:", verified_author)


if __name__ == "__main__":
    run_demo()
