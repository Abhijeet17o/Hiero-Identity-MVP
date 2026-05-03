import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


def generate_keypair():
    """Generate an Ed25519 keypair and return (priv_obj, pub_obj, priv_pem, pub_pem)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return priv, pub, priv_pem, pub_pem


def pubkey_to_did(pub: Ed25519PublicKey) -> str:
    """Create a simple did:ed25519:<base64url(pub)> identifier for the public key."""
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return f"did:ed25519:{b64}"
