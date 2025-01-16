from utils import (
    read,
    publish_resource,
)
from anoncreds import (
    Schema,
    CredentialDefinition,
    RevocationRegistryDefinition,
)

issuer = read("../docs/.well-known/did.json")["alsoKnownAs"][0]
schema_name = "Sample"
schema_version = "1.0"
schema_attributes = ["firstName", "lastName"]

schema = Schema.create(schema_name, schema_version, issuer, schema_attributes)
schema_id = publish_resource(issuer, schema.to_dict(), "AnonCredsSchema")

cred_def_pub, cred_def_priv, cred_def_correctness = CredentialDefinition.create(
    schema_id, schema, issuer, schema_name, "CL", support_revocation=True
)
cred_def_id = publish_resource(issuer, cred_def_pub.to_dict(), "AnonCredsCredDef")

(rev_reg_def_pub, rev_reg_def_private) = RevocationRegistryDefinition.create(
    cred_def_id, cred_def_pub, issuer, schema_name, "CL_ACCUM", 10
)
rev_reg_id = publish_resource(issuer, rev_reg_def_pub.to_dict(), "AnonCredsRevRegDef")
