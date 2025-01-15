import json
import os
from utils import (
    sign,
    timestamp,
    generate_hash,
    key_from_seed,
    encode_public_key,
)

update_key = key_from_seed(os.getenv("DID_UPDATE_SEED"))
controller_key = key_from_seed(os.getenv("DID_CONTROLLER_SEED"))

pre_log_entry = {
    "versionId": r"{SCID}",
    "versionTime": timestamp(),
    "parameters": {
        "method": "did:webvh:0.5",
        "scid": r"{SCID}",
        "updateKeys": [encode_public_key(update_key)],
    },
    "state": {
        "@context": ["https://www.w3.org/ns/cid/v1"],
        "id": r"did:webvh:{SCID}:sample.identifier.me",
        "authentication": [r"did:webvh:{SCID}:sample.identifier.me#key-01"],
        "assertionmethod": [r"did:webvh:{SCID}:sample.identifier.me#key-01"],
        "verificationMethod": [
            {
                "id": r"did:webvh:{SCID}:sample.identifier.me#key-01",
                "type": "Multikey",
                "controller": r"did:webvh:{SCID}:sample.identifier.me",
                "publicKeyMultibase": encode_public_key(controller_key),
            }
        ],
    },
}

scid = generate_hash(pre_log_entry)
log_entry = json.loads(json.dumps(pre_log_entry).replace(r"{SCID}", scid))
log_entry["versionId"] = f"1-{generate_hash(log_entry)}"
signed_log_entry = sign(log_entry, update_key)
did_document = signed_log_entry["state"]
did_webvh = did_document["id"]
did_document = json.loads(
    json.dumps(did_document).replace(
        did_webvh, "did:web:" + "".join(did_webvh.split(":")[3:])
    )
)
did_document["alsoKnownAs"] = [did_webvh]

with open("../docs/.well-known/did.json", "w") as f:
    f.write(json.dumps(did_document, indent=2))

with open("../docs/.well-known/did.jsonl", "w") as f:
    f.write(json.dumps(signed_log_entry) + "\n")
