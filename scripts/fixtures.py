from utils import (
    DOMAIN,
    update_key,
    controller_key,
    timestamp,
    encode_public_key,
)

scid_placeholder = r"{SCID}"
pre_log_entry = {
    "versionId": scid_placeholder,
    "versionTime": timestamp(),
    "parameters": {
        "scid": scid_placeholder,
        "method": "did:webvh:0.5",
        "updateKeys": [encode_public_key(update_key)],
    },
    "state": {
        "@context": ["https://www.w3.org/ns/cid/v1"],
        "id": f"did:webvh:{scid_placeholder}:{DOMAIN}",
        "authentication": [f"did:webvh:{scid_placeholder}:{DOMAIN}#key-01"],
        "assertionmethod": [f"did:webvh:{scid_placeholder}:{DOMAIN}#key-01"],
        "verificationMethod": [
            {
                "id": f"did:webvh:{scid_placeholder}:{DOMAIN}#key-01",
                "type": "Multikey",
                "controller": f"did:webvh:{scid_placeholder}:{DOMAIN}",
                "publicKeyMultibase": encode_public_key(controller_key),
            }
        ],
    },
}
