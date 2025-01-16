import jcs
import os
import json
from multiformats import multibase, multihash
from aries_askar import Key, KeyAlg
from aries_askar.bindings import LocalKeyHandle
from hashlib import sha256
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()
DOMAIN = os.getenv("DOMAIN")
DID_UPDATE_SEED = os.getenv("DID_UPDATE_SEED")
DID_CONTROLLER_SEED = os.getenv("DID_CONTROLLER_SEED")


def key_from_seed(seed):
    return Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, seed)


update_key = key_from_seed(DID_UPDATE_SEED)
controller_key = key_from_seed(DID_CONTROLLER_SEED)


def timestamp():
    return str(
        datetime.now(timezone.utc).isoformat("T", "seconds").replace("+00:00", "Z")
    )


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


def replace_all(document, search, replace):
    return json.loads(json.dumps(document).replace(search, replace))


def write(path, content):
    with open(path, "w") as f:
        f.write(content)


def read(path):
    with open(path, "r") as f:
        return json.loads(f.read())


def publish_resource(did, content, resource_type):
    digest = generate_multihash(content)
    resource_id = f"{did}/resources/{digest}.json"
    resource = create_resource(
        resource_id,
        content,
        {"resourceId": digest, "resourceType": resource_type},
    )
    signed_resource = sign(resource, controller_key, f"{did}#key-01")
    write(f"../docs/resources/{digest}.json", json.dumps(signed_resource, indent=2))
    return resource_id
