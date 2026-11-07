# OpenBao seal and unseal options

This document covers every seal mechanism OpenBao 2.7 supports, how to choose
one for a deployment, and the operational rules that keep an
OpenBao-backed KMS recoverable.

It is written for operators. The key point for application teams is simple:
**the seal protects OpenBao's own storage-encryption key. It does not change how
Credo keys are created, signed with, or rotated.** Never rotate a Transit
signing key to rotate a seal: a new Transit key version changes the public key
and breaks every DID document and credential that references it.

---

## 1. What a seal actually does

OpenBao encrypts its storage with a root key. At rest, the root key is itself
encrypted with a key-encryption key (KEK) that comes from the seal. On startup
OpenBao is **sealed**: it can read the encrypted root key but cannot use it.

Unsealing reconstructs the KEK, decrypts the root key, and brings the node
online. The KEK never leaves the seal mechanism for auto-unseal options.

There are two families:

| Family | How the KEK is obtained | Operator experience |
| --- | --- | --- |
| Shamir | Unseal key shards are entered manually and combined | Manual unseal after every restart |
| Auto-unseal | A KMS, HSM, another OpenBao cluster, or a static key supplies the KEK | Node unseals itself at startup |

Auto-unseal removes the manual step. It does not remove the need to protect the
trust anchor: whoever can use the KMS key, HSM key, Transit key, or static key
can unseal a copy of the OpenBao storage. Backups and the trust anchor must be
protected together.

Two credential systems exist and are often confused:

- **Seal credentials** unseal the node. They are Shamir shards, recovery keys,
  or credentials for the external seal.
- **Client credentials** (AppRole, Kubernetes, token) authorize API calls after
  the node is unsealed. They have nothing to do with unsealing.

A sealed node rejects client requests even if the AppRole credentials are valid.
The plugin maps that failure to a distinct `sealed` error instead of reporting a
generic network failure.

---

## 2. Options at a glance

| Seal | Type | Best for | Main trade-off |
| --- | --- | --- | --- |
| `shamir` | Built-in, default | Small self-hosted installs, break-glass clusters, offline roots | Manual unseal after every restart |
| `static` | Built-in | Platforms that already inject a secret from another secret manager | The static key becomes a high-value secret |
| `transit` | Built-in | Unattended on-prem or multi-cluster deployments without an HSM | Depends on a second OpenBao/Vault cluster |
| `pkcs11` | KMS plugin | Regulated deployments with an HSM | HSM, vendor library, and plugin packaging |
| `kmip` | Built-in | Environments that already have a KMIP KMS or HSM | KMIP server must meet OpenBao's requirements |
| `awskms` | KMS plugin | AWS-hosted deployments | Cloud lock-in and IAM design |
| `gcpckms` | KMS plugin | GCP-hosted deployments | Cloud lock-in and IAM design |
| `azurekeyvault` | KMS plugin | Azure-hosted deployments | Cloud lock-in and Entra ID design |
| `ocikms` | KMS plugin | OCI-hosted deployments | Cloud lock-in and IAM design |
| `alicloudkms` | KMS plugin | Alibaba Cloud deployments | Cloud lock-in and IAM design |
| `ovhcloud` | KMS plugin | OVHcloud-hosted deployments | Provider-specific |
| `tcloudpublic` | KMS plugin | T Cloud Public deployments | Provider-specific |
| `securosys` | KMS plugin | Securosys Primus HSM deployments | Vendor-specific |

Since OpenBao 2.6, seals that are not built in are installed as external KMS
plugins. OpenBao 2.7 moved several previously built-in vendor seals to plugins.
A plugin is declared next to the seal:

```hcl
plugin "kms" "pkcs11" {
  command = "openbao-plugin-kms-pkcs11"
}

seal "pkcs11" {
  # ...
}
```

When a provider exists both built in and as a plugin, the plugin wins. Plan the
plugin binary, its version, and its restart behaviour as part of the deployment,
not as an afterthought.

---

## 3. Shamir (the default)

Shamir splits the KEK into `key-shares` shards and requires `key-threshold` of
them to unseal. OpenBao 2.x uses Shamir for the root key unless a `seal` stanza
is present.

```hcl
# No seal stanza: Shamir is the default.
storage "postgresql" {
  connection_url = "postgres://openbao:...@postgres:5432/openbao?sslmode=require&search_path=openbao"
}
```

Initialise with an explicit policy:

```bash
bao operator init \
  -key-shares=5 \
  -key-threshold=3 \
  -recovery-shares=5 \
  -recovery-threshold=3
```

Then unseal each node:

```bash
bao operator unseal   # repeat with three different shards
bao status
```

**Use it when**

- the cluster is small and restarts are supervised;
- it is a break-glass or offline root cluster;
- there is no KMS or HSM, and unattended restarts are not required.

**Do not**

- store all shards together on the same host, in the same repository, or in the
  same secret manager as the OpenBao database backup;
- automate unseal by writing shards into a Kubernetes Secret and calling
  `bao operator unseal` from an init container. That converts Shamir into a
  weak static seal with extra steps. Use the `static` seal instead if a secret
  manager is the trust anchor.

**Rotation:** rekey with `bao operator rekey`, or change the share/threshold
policy with `bao operator rekey -init`. Old shards stop working after the rekey
completes. Keep an offline copy of the new shards before discarding the old
ones.

**Failure mode:** after a full cluster restart nobody can unseal until the
threshold of shard holders is available. This is a deliberate availability
trade-off; document the call tree and test it.

---

## 4. Static key auto-unseal

The `static` seal uses a 32-byte AES-256-GCM key supplied directly, through an
environment variable (`env://`), or through a file (`file://`).

```hcl
seal "static" {
  current_key_id  = "2026-11-01"
  current_key     = "file:///openbao/secrets/unseal-2026-11-01.key"
  previous_key_id = "2026-08-01"
  previous_key    = "file:///openbao/secrets/unseal-2026-08-01.key"
}
```

Create the key with a cryptographically secure source:

```bash
openssl rand -out /openbao/secrets/unseal-2026-11-01.key 32
chmod 0400 /openbao/secrets/unseal-2026-11-01.key
```

**Use it when**

- the platform already has a trusted secret source (Kubernetes with an external
  secrets operator, a cloud secret manager, a configuration-management system
  with sealed secrets);
- Shamir would be automated badly and an HSM or cloud KMS is not available.

**Security requirements**

- The file must be readable only by the OpenBao process, never baked into an
  image or a Helm values file.
- The secret source must have its own access control, audit, and rotation.
- Back up the static key separately from the OpenBao storage backup, but ensure
  a disaster recovery runbook can retrieve both.
- Treat the key as equivalent to the OpenBao root key.

**Rotation:** create a new 32-byte key, set `previous_key`/`previous_key_id` to
the old value and `current_key`/`current_key_id` to the new one, then restart.
Keep the previous key until all nodes have written with the new key. The key id
must change whenever the key value changes.

**Failure mode:** if the secret is missing or has the wrong length, the node
stays sealed. If the secret is exposed, an attacker with a storage backup can
decrypt it.

---

## 5. Transit seal

The `transit` seal uses a Transit key in another OpenBao or Vault cluster as the
KEK. The unseal cluster holds the wrapping key; the production cluster only
needs encrypt/decrypt permission on that one key.

```hcl
seal "transit" {
  address         = "https://openbao-unseal.example.com:8200"
  token           = "env://BAO_SEAL_TOKEN"
  key_name        = "openbao-seal"
  mount_path      = "transit/"
  disable_renewal = "false"

  tls_ca_cert     = "/etc/openbao/tls/ca.pem"
  tls_server_name = "openbao-unseal.example.com"
}
```

The token needs only:

```hcl
path "transit/encrypt/openbao-seal" {
  capabilities = ["update"]
}

path "transit/decrypt/openbao-seal" {
  capabilities = ["update"]
}
```

Recommended token properties: orphan, periodic, no short max TTL, and renewed
by OpenBao itself (`disable_renewal = "false"`).

**Use it when**

- nodes must restart unattended on-prem;
- there is no HSM and no cloud KMS;
- a second, smaller OpenBao cluster can be operated as the trust anchor.

This is the recommended unattended option when the only alternative would be
storing Shamir shards in Kubernetes. The unseal cluster should use a different
failure domain and its own seal (Shamir offline, HSM, or cloud KMS). Do not make
the two clusters depend on each other for unsealing.

**Rotation:** rotate the Transit key on the unseal cluster. OpenBao's seal reads
the latest version for encryption and keeps old versions for decryption, so
rotation is safe. Do not delete old key versions.

**Failure mode:** if the unseal cluster is unavailable at startup, the
production node stays sealed. Keep the unseal cluster highly available, monitor
it separately, and document the break-glass path.

---

## 6. PKCS#11 (HSM)

The `pkcs11` seal uses a key inside a PKCS#11-compatible HSM. OpenBao requires
the key material to exist before initialisation; it does not create the HSM key.

```hcl
plugin "kms" "pkcs11" {
  command = "openbao-plugin-kms-pkcs11"
}

seal "pkcs11" {
  lib         = "/usr/lib64/pkcs11/libvendor.so"
  token_label = "OpenBao"
  pin         = "env://BAO_HSM_PIN"
  key_label   = "openbao-root"
  mechanism   = "AES_GCM"
}
```

Create the key with the HSM vendor tooling, for example:

```bash
pkcs11-tool --module /usr/lib64/pkcs11/libvendor.so \
  --token-label OpenBao --pin "$BAO_HSM_PIN" \
  --keygen --key-type aes:32 --label openbao-root
```

**Use it when**

- regulation or policy requires key material to stay in an HSM;
- the deployment can operate HSM high availability, backups, and firmware
  upgrades;
- the HSM vendor supports the PKCS#11 mechanisms OpenBao needs (`AES_GCM`, or
  `RSA_PKCS_OAEP` with a supported hash).

**Operational notes**

- One of `slot`, `serial`, or `token_label` must identify the token.
- `pin` should come from an environment variable or a protected file, not the
  configuration file.
- `disable_software_encryption = true` forces RSA-OAEP encryption into the HSM.
  Some HSMs implement decryption but not encryption, so test it.
- PKCS#11 is an external KMS plugin in OpenBao 2.7. Pin the plugin version,
  ship it with the image, and monitor plugin crashes.

**Rotation:** generate a new key under a new label, update `key_label`, restart,
and keep the old key until all data has been re-encrypted by normal operation.
Never delete the old HSM key while old storage may still be needed.

**Failure mode:** HSM unavailability, a changed PIN, a firmware upgrade that
renumbers slots, or a missing vendor library all leave the node sealed.

---

## 7. KMIP

The `kmip` seal uses a KMIP KMS or HSM. As with PKCS#11, the wrapping key must
exist before OpenBao initialisation and must be in the `active` state.

```hcl
seal "kmip" {
  endpoint    = "kmip.example.com:5696"
  kms_key_id  = "00000000-0000-0000-0000-000000000000"
  client_cert = "/etc/openbao/kmip/client.pem"
  client_key  = "/etc/openbao/kmip/client.key"
  ca_cert     = "/etc/openbao/kmip/ca.pem"
  encrypt_alg = "AES_GCM"
}
```

The KMIP server must support KMIP 1.2, 1.3, or 1.4, encrypt and decrypt, and
`AES_GCM` or `RSA_OAEP_SHA256/384/512`.

**Use it when**

- a KMIP-capable appliance already exists and is the organisation's standard
  key manager;
- PKCS#11 is not available or not approved, but the appliance exposes KMIP.

**Rotation:** create or rotate the key in the KMIP server, update
`kms_key_id`, and restart. Old keys must remain enabled for decryption.

**Failure mode:** certificate expiry, a network policy change, or the appliance
being in a degraded state leaves the node sealed.

---

## 8. Cloud KMS seals

The cloud seals use a customer-managed key in the provider's KMS. They are the
default recommendation for managed cloud deployments.

### AWS KMS

```hcl
plugin "kms" "awskms" {
  command = "openbao-plugin-kms-awskms"
}

seal "awskms" {
  region     = "eu-west-1"
  kms_key_id = "arn:aws:kms:eu-west-1:111122223333:key/..."
  # Prefer the instance/task IAM role. Static keys are supported but worse.
  # access_key    = "env://AWS_ACCESS_KEY_ID"
  # secret_key    = "env://AWS_SECRET_ACCESS_KEY"
  # session_token = "env://AWS_SESSION_TOKEN"
}
```

Use a dedicated KMS key, a key policy that allows only the OpenBao role, and
CloudTrail alerts on `Decrypt`. Prefer IAM roles over static credentials.

### GCP Cloud KMS

```hcl
plugin "kms" "gcpckms" {
  command = "openbao-plugin-kms-gcpckms"
}

seal "gcpckms" {
  project    = "example-project"
  region     = "europe-west1"
  key_ring   = "openbao"
  crypto_key = "seal"
  # credentials = "/etc/openbao/gcp-credentials.json"
}
```

Prefer Workload Identity over a service-account JSON key.

### Azure Key Vault

```hcl
plugin "kms" "azurekeyvault" {
  command = "openbao-plugin-kms-azurekeyvault"
}

seal "azurekeyvault" {
  tenant_id     = "00000000-0000-0000-0000-000000000000"
  vault_name    = "openbao"
  key_name      = "seal"
  # Prefer a managed identity over client_secret.
  # client_id     = "00000000-0000-0000-0000-000000000000"
  # client_secret = "env://AZURE_CLIENT_SECRET"
}
```

Grant only `wrapKey`/`unwrapKey` (or the equivalent crypto permissions) to the
OpenBao identity, and enable Key Vault audit logging.

### OCI KMS, AliCloud KMS, OVHcloud KMS, T Cloud Public KMS

The same pattern applies: create a dedicated wrapping key, give the OpenBao
workload a least-privilege identity, install the provider's `kms` plugin, and
put provider-specific connection and credential fields in the `seal` block.

```hcl
# OCI
seal "ocikms" {
  key_id             = "ocid1.key.oc1..."
  crypto_endpoint    = "https://...-crypto.kms.eu-frankfurt-1.oraclecloud.com"
  management_endpoint = "https://...-management.kms.eu-frankfurt-1.oraclecloud.com"
  auth_type          = "instance_principal"
}

# AliCloud
seal "alicloudkms" {
  region     = "eu-central-1"
  kms_key_id = "alias/openbao-seal"
}

# OVHcloud
seal "ovhcloud" {
  okms_endpoint = "https://eu-west-rbx.okms.ovh.net"
  # client_id / client_secret from the OVHcloud IAM identity
}

# T Cloud Public
seal "tcloudpublic" {
  region     = "eu-de"
  kms_key_id = "your-key-id"
}
```

**Rotation:** rotate the cloud KMS key and keep old versions enabled for
decryption. OpenBao records the key version with the encrypted data.

**Failure mode:** an expired credential, a revoked IAM role, a key policy
change, or a regional KMS outage leaves the node sealed. Cloud KMS quotas and
regional availability are part of the OpenBao availability model.

### Securosys Primus HSM

Securosys exposes a dedicated seal mechanism rather than plain PKCS#11.

```hcl
plugin "kms" "securosys" {
  command = "openbao-plugin-kms-securosys"
}

seal "securosys" {
  # Connection, token, and key-label fields from the Securosys guide.
}
```

Follow the Securosys/OpenBao integration guide for the exact fields and for
creating the key in the Primus HSM.

---

## 9. Choosing a seal

The choice is driven by where the deployment runs and whether restarts are
unattended.

| Deployment | Recommended seal | Why |
| --- | --- | --- |
| Local development / demo | Shamir 1-of-1, or `static` for convenience | Fast, disposable, no external dependency |
| Small self-hosted, supervised restarts | Shamir 3-of-5 | No extra infrastructure, strong break-glass story |
| Self-hosted, unattended restarts, no HSM | `transit` from a dedicated unseal cluster | Auto-unseal without storing shards in Kubernetes |
| Self-hosted with an approved HSM | `pkcs11` (or `kmip`) | Key material stays in the HSM |
| Existing enterprise secret manager | `static` with `env://` or `file://` | Chains OpenBao to the existing trust anchor |
| Managed deployment on AWS | `awskms` | Managed availability, IAM, CloudTrail |
| Managed deployment on Azure | `azurekeyvault` | Managed availability, managed identity, audit |
| Managed deployment on GCP | `gcpckms` | Managed availability, Workload Identity, audit |
| Existing KMIP appliance | `kmip` | Reuses the standard key manager |

Rules of thumb:

1. **Production must not use Shamir with automated shard injection.** If a
   machine can unseal without a human, use an auto-seal designed for it.
2. **The unseal trust anchor must live in a different failure domain from the
   OpenBao data.** A Transit seal whose unseal cluster shares the same database,
   cloud account, or Kubernetes cluster is not a second trust anchor.
3. **Prefer managed identities over static credentials** for every cloud seal.
4. **Do not use the same KMS key for OpenBao's seal and for application
   secrets.** Separate keys make rotation, audit, and incident response
   unambiguous.
5. **Test restore, not just backup.** A database backup plus a working seal is
   the only recoverable combination.

---

## 10. Initialisation and recovery runbooks

### First initialisation with auto-unseal

```bash
# 1. Configure the seal stanza and start OpenBao. It starts sealed.
bao status

# 2. Initialise once. With auto-unseal, these are recovery keys, not unseal keys.
bao operator init \
  -recovery-shares=5 \
  -recovery-threshold=3

# 3. The node auto-unseals because the seal is available.
bao status
```

Store the recovery keys offline. They are required to generate a root token or
recover from a lost approle/token, not for routine restarts.

### First initialisation with Shamir

```bash
bao operator init -key-shares=5 -key-threshold=3
# Distribute the unseal keys to five holders.
# Store the initial root token separately, then revoke it after creating
# a break-glass admin and the AppRole used by the Credo agent.
```

### Migrating Shamir to auto-unseal

```bash
# On the leader, with the cluster healthy:
bao operator unseal -migrate
# Enter the existing Shamir shards when prompted.
# Restart the leader with the new seal stanza.
# Then restart standbys one at a time.
bao status
```

Always take a storage snapshot before a seal migration and verify it restores
in a non-production environment.

### Migrating between auto-seals

Keep the old seal block with `disabled = "true"`, add the new seal block, and
follow the seal migration procedure. Do not delete the old KMS/HSM key until the
migration is complete and a restore has been tested.

### Break-glass when the seal is unavailable

1. Confirm the failure is the seal, not the network or the client token:
   `bao status` reports `Sealed true`; the logs name the seal provider.
2. Restore the seal dependency (KMS permissions, HSM connectivity, unseal
   cluster availability, static secret mount).
3. If the dependency cannot be restored, use the recovery keys with
   `bao operator unseal` (auto-seal clusters) or the Shamir shards.
4. Do not re-initialise an existing cluster. `bao operator init` on existing
   storage destroys the ability to decrypt it.

### Disaster recovery

A recoverable OpenBao deployment needs all three:

1. A PostgreSQL backup of the OpenBao database, including the `openbao` schema.
2. The seal trust anchor: the KMS key, HSM key, Transit key, or static key.
3. The recovery keys or Shamir shards, stored separately from 1 and 2.

A backup without the trust anchor is ciphertext. A trust anchor without the
backup is an empty cluster. Recovery keys without either cannot reconstruct
application keys.

Restore procedure:

```bash
# 1. Provision PostgreSQL and restore the openbao database.
# 2. Start OpenBao with the same seal configuration and the same trust anchor.
# 3. Verify the node unseals and the Transit keys are listed.
bao status
bao list transit/keys
# 4. Verify a known DID resolves and a test signature verifies.
# 5. Only then point the Credo agent at the restored cluster.
```

---

## 11. What must never be rotated or exported

The seal protects storage. Credo keys are different.

- **Never rotate a Transit key that backs a DID, X.509 certificate, or issued
  credential.** Rotation creates a new key version and changes the public key.
  The key id then resolves to a different public key and every existing
  verification breaks.
- **Never enable export on production Transit keys.** Export turns a
  non-exportable signing key into extractable key material.
- **Never delete a Transit key while a DID or credential references it.**
  Deletion is irreversible for the key version history.
- **Do not reuse one Transit key across tenants.** The plugin namespaces keys by
  deployment and tenant scope, and the AppRole policy should not allow listing
  other scopes.

The AppRole policy should deny these paths for the Credo agent's role:

```hcl
path "transit/keys/*/rotate" {
  capabilities = ["deny"]
}

path "transit/export/*" {
  capabilities = ["deny"]
}

path "transit/backup/*" {
  capabilities = ["deny"]
}
```

Key creation, import, and deletion are separate capabilities. If
`writeEnabled: false` is set on the backend, the deployment should also use a
read/sign-only AppRole so a compromised agent cannot create or delete keys even
if the application flag is bypassed.

---

## 12. PostgreSQL storage notes

When PostgreSQL is OpenBao's storage backend, use a
dedicated `openbao` database and the `openbao` schema. The schema is
selected through the connection `search_path`; the PostgreSQL storage stanza has
no separate `schema` parameter.

```hcl
storage "postgresql" {
  connection_url = "postgres://openbao:...@postgres:5432/openbao?sslmode=require&search_path=openbao"
  max_idle_connections = 5
  max_parallel       = 10
}
```

```sql
CREATE ROLE openbao LOGIN PASSWORD '...';
CREATE DATABASE openbao OWNER openbao;
\c openbao
CREATE SCHEMA IF NOT EXISTS openbao AUTHORIZATION openbao;
ALTER ROLE openbao SET search_path TO openbao, public;
```

This is OpenBao's storage backend, not the `database/` secrets engine. Do not
create dynamic database credentials through OpenBao for the application
database; the application keeps its own credentials.

In HA, OpenBao uses `openbao_ha_locks`; both tables live in the `openbao` schema
when `search_path` is set. Back up the database with `pg_dump -n openbao` or a
physical backup that includes the schema, and test the restore with the same
seal configuration.

---

## 13. Operational checklist

Before going live:

- [ ] Seal mechanism chosen and documented, with an owner.
- [ ] Shamir shards or recovery keys distributed to separate holders.
- [ ] Auto-seal credentials use a managed identity, not a long-lived secret.
- [ ] Seal health check enabled (default) and monitored in OpenBao logs.
- [ ] PostgreSQL backup includes the `openbao` schema.
- [ ] Trust anchor backed up separately from the database backup.
- [ ] Restore tested end to end, including `bao list transit/keys`.
- [ ] Seal migration procedure tested in staging.
- [ ] AppRole policy denies key rotation, export, and backup.
- [ ] The `writeEnabled: false` rollback procedure is documented.
- [ ] Alerts on `Sealed true`, seal health-check failures, and KMS/HSM errors.
- [ ] No Transit signing key rotation in any runbook.

During an incident:

1. Check `bao status` for `Sealed`.
2. Check OpenBao logs for the seal provider's error, not just the HTTP 503.
3. Check the seal dependency (KMS permissions, HSM session, unseal cluster,
   static secret).
4. Check the AppRole token separately; a valid token cannot unseal a node.
5. If the node is unsealed but requests fail, the problem is authorization or
   the Transit mount, not the seal.

---

## 14. References

- OpenBao seal concepts: <https://openbao.org/docs/concepts/seal/>
- OpenBao `seal` stanza: <https://openbao.org/docs/configuration/seal/>
- OpenBao PostgreSQL storage: <https://openbao.org/docs/configuration/storage/postgresql/>
- OpenBao Transit secrets engine: <https://openbao.org/docs/secrets/transit/>
- OpenBao plugin system: <https://openbao.org/docs/plugins/>
- OpenBao deprecation notices: <https://openbao.org/community/deprecation/>
