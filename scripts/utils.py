import jcs
import os
from multiformats import multibase, multihash
from aries_askar import Key, KeyAlg
from aries_askar.bindings import LocalKeyHandle
from hashlib import sha256
from datetime import datetime, timezone

DOMAIN = os.getenv("DOMAIN")
DID_UPDATE_SEED = os.getenv("DID_UPDATE_SEED")
DID_CONTROLLER_SEED = os.getenv("DID_CONTROLLER_SEED")

def timestamp():
    return str(
        datetime.now(timezone.utc).isoformat("T", "seconds").replace("+00:00", "Z")
    )


def key_from_seed(seed):
    return Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, seed)


def encode_public_key(key, prefix="ed01"):
    return multibase.encode(
        bytes.fromhex(f"{prefix}{key.get_public_bytes().hex()}"),
        "base58btc",
    )


def generate_hash(value):
    return multibase.encode(
        multihash.digest(jcs.canonicalize(value), "sha2-256"), "base58btc"
    )[1:]


def generate_multihash(value):
    return multibase.encode(
        multihash.digest(jcs.canonicalize(value), "sha2-256"), "base58btc"
    )


def sign(document, key, verification_method=None):
    proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "assertionMethod",
        "verificationMethod": (
            verification_method
            if verification_method
            else f"did:key:{encode_public_key(key)}#{encode_public_key(key)}"
        ),
    }

    proof["proofValue"] = multibase.encode(
        key.sign_message(
            sha256(jcs.canonicalize(proof)).digest()
            + sha256(jcs.canonicalize(document)).digest()
        ),
        "base58btc",
    )
    return document | {"proof": proof}


def create_resource(resource_id, content, metadata):
    return {
        "@context": [
            f"https://{DOMAIN}/attested-resource/v1",
            "https://w3id.org/security/data-integrity/v2",
        ],
        "type": ["AttestedResource"],
        "id": resource_id,
        "resourceContent": content,
        "resourceMetadata": metadata,
    }
