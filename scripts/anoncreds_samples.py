import json
import os
from utils import (
    sign,
    timestamp,
    create_resource,
    generate_multihash,
    key_from_seed,
)
from anoncreds import (
    Schema,
    CredentialDefinition,
    RevocationRegistryDefinition,
    RevocationStatusList,
)

key = key_from_seed(os.getenv("DID_CONTROLLER_SEED"))
with open("../docs/.well-known/did.json", "r") as f:
    issuer = json.loads(f.read())["alsoKnownAs"][0]

schema_name = "Sample"
schema_version = "1.0"
schema = Schema.create(schema_name, schema_version, issuer, ["firstName", "lastName"])
schema_digest = generate_multihash(schema.to_dict())
schema_id = f"{issuer}/resources/{schema_digest}.json"
schema_resource = create_resource(
    schema_id,
    schema.to_dict(),
    {"resourceId": schema_digest, "resourceType": "AnonCredsSchema"},
)
signed_schema_resource = sign(schema_resource, key, f'{issuer}#key-01')
with open(f'../docs/resources/{schema_digest}.json', 'w') as f:
    f.write(json.dumps(signed_schema_resource, indent=2))

cred_def_pub, cred_def_priv, cred_def_correctness = CredentialDefinition.create(
    schema_id, schema, issuer, schema_name, "CL", support_revocation=True
)
cred_def_digest = generate_multihash(cred_def_pub.to_dict())
cred_def_id = f"{issuer}/resources/{cred_def_digest}.json"
cred_def_resource = create_resource(
    cred_def_id,
    cred_def_pub.to_dict(),
    {"resourceId": cred_def_digest, "resourceType": "AnonCredsCredDef"},
)
signed_cred_def_resource = sign(cred_def_resource, key, f'{issuer}#key-01')
with open(f'../docs/resources/{cred_def_digest}.json', 'w') as f:
    f.write(json.dumps(signed_cred_def_resource, indent=2))

(rev_reg_def_pub, rev_reg_def_private) = RevocationRegistryDefinition.create(
    cred_def_id, cred_def_pub, issuer, schema_name, "CL_ACCUM", 10
)
rev_reg_digest = generate_multihash(rev_reg_def_pub.to_dict())
rev_reg_id = f"{issuer}/resources/{rev_reg_digest}.json"
rev_reg_resource = create_resource(
    rev_reg_id,
    rev_reg_def_pub.to_dict(),
    {"resourceId": rev_reg_digest, "resourceType": "AnonCredsRevRegDef"},
)
signed_rev_reg_resource = sign(rev_reg_resource, key, f'{issuer}#key-01')
with open(f'../docs/resources/{rev_reg_digest}.json', 'w') as f:
    f.write(json.dumps(signed_rev_reg_resource, indent=2))

# time_create_rev_status_list = 12
# revocation_status_list = RevocationStatusList.create(
#     cred_def_pub,
#     rev_reg_id,
#     rev_reg_def_pub,
#     rev_reg_def_private,
#     issuer,
#     True,
#     time_create_rev_status_list,
# )
