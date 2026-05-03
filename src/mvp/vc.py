import json
import os
import base64
import datetime
from typing import Dict, Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey


def _canonicalize(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def issue_vc(issuer_priv: Ed25519PrivateKey, issuer_pub_pem: str, subject_did: str, subject_email: str) -> Dict[str, Any]:
    """Issue a minimal Verifiable Credential linking subject DID to an email, signed by issuer."""
    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "urn:uuid:demo-" + base64.urlsafe_b64encode(os.urandom(6)).decode().rstrip("="),
        "type": ["VerifiableCredential", "ContributorCredential"],
        "issuer": "urn:issuer:demo",
        "issuanceDate": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "credentialSubject": {"id": subject_did, "email": subject_email},
    }

    serialized = _canonicalize(credential)
    signature = issuer_priv.sign(serialized)
    proof = {
        "type": "Ed25519Signature2020",
        "created": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "urn:pubkey:demo",
        "publicKeyPem": issuer_pub_pem,
        "signatureValue": base64.b64encode(signature).decode("ascii"),
    }
    credential["proof"] = proof
    return credential


def verify_vc(credential: Dict[str, Any]) -> bool:
    """Verify the VC signature using the embedded public key in proof.publicKeyPem."""
    proof = credential.get("proof")
    if not proof:
        return False
    pub_pem = proof.get("publicKeyPem")
    if not pub_pem:
        return False
    sig_b64 = proof.get("signatureValue")
    if not sig_b64:
        return False

    # Recreate the signed payload (credential without proof)
    cred_copy = {k: v for k, v in credential.items() if k != "proof"}
    serialized = _canonicalize(cred_copy)
    signature = base64.b64decode(sig_b64)

    pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
    if not isinstance(pub, Ed25519PublicKey):
        return False
    try:
        pub.verify(signature, serialized)
        return True
    except Exception:
        return False


def credential_subject_email(credential: Dict[str, Any]) -> str:
    cs = credential.get("credentialSubject", {})
    return cs.get("email")
