import json
from utils import (
    update_key,
    sign,
    write,
    generate_hash,
    replace_all,
)
from fixtures import scid_placeholder, pre_log_entry

log_entry = replace_all(pre_log_entry, scid_placeholder, generate_hash(pre_log_entry))
log_entry["versionId"] = f"1-{generate_hash(log_entry)}"

signed_log_entry = sign(log_entry, update_key)

did_document = replace_all(
    signed_log_entry["state"],
    signed_log_entry["state"]["id"],
    "did:web:" + "".join(signed_log_entry["state"]["id"].split(":")[3:]),
) | {"alsoKnownAs": [signed_log_entry["state"]["id"]]}

write("../docs/.well-known/did.json", json.dumps(did_document, indent=2))
write("../docs/.well-known/did.jsonl", json.dumps(signed_log_entry) + "\n")
