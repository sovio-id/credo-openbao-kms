# @sovio-id/credo-openbao-kms

[![npm](https://img.shields.io/npm/v/@sovio-id/credo-openbao-kms)](https://www.npmjs.com/package/@sovio-id/credo-openbao-kms)
[![JSR](https://jsr.io/badges/@sovio-id/credo-openbao-kms)](https://jsr.io/@sovio-id/credo-openbao-kms)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

A key management service (KMS) backend for [Credo](https://credo.js.org) that
keeps signing keys in [OpenBao](https://openbao.org)'s Transit secrets engine.

Private keys for Ed25519, P-256, P-384, P-521 and RSA are generated or imported
inside OpenBao and never returned to the application. The agent asks OpenBao for
signatures; OpenBao enforces policy and records every operation in its audit
log. secp256k1 and X25519, which Transit cannot represent, can optionally be
stored in an OpenBao KV v2 mount.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Authentication](#authentication)
- [Configuration](#configuration)
- [Supported key types and operations](#supported-key-types-and-operations)
- [Importing existing keys](#importing-existing-keys)
- [Key ids and multi-tenancy](#key-ids-and-multi-tenancy)
- [Operating in production](#operating-in-production)
- [OpenBao policy](#openbao-policy)
- [Security model](#security-model)
- [Limitations](#limitations)
- [Implementation notes](#implementation-notes)
- [Development](#development)
- [Supply chain](#supply-chain)
- [Contributing and security](#contributing-and-security)
- [License](#license)

## Features

- **Non-exportable signing keys.** Ed25519, P-256/384/521 and RSA 2048/3072/4096
  keys are created inside Transit. A compromised agent can request signatures
  but cannot read the key.
- **Bring your own key.** Existing keys, for example the key behind an X.509
  issuer certificate, are imported through Transit's BYOK endpoint with
  RSA-OAEP + AES-KWP wrapping, so plaintext key material never crosses the
  network.
- **Works with Credo's KMS routing.** Operations this backend cannot perform
  (`randomBytes`, symmetric encryption) are routed by Credo to another backend
  such as Askar or the Node.js KMS.
- **Multi-tenant safe.** Transit key names are derived from a hash of the
  deployment and tenant scope, so tenants never share or see each other's keys,
  and tenant ids never appear in OpenBao.
- **Production auth.** AppRole login with lease tracking, renewal and re-login,
  or any token provider you supply.
- **Operational controls.** Health checks that distinguish sealed from
  unreachable, a write kill-switch for rollbacks, and per-tenant key purge.
- **Local verification.** Signatures are verified with `node:crypto` (and
  `@noble/curves` for secp256k1) using public keys only, so verification also
  works for keys this backend does not hold.

## Requirements

| Component | Version |
| --- | --- |
| Credo (`@credo-ts/core`) | `^0.7.0` (peer dependency; tested with 0.7.4) |
| Node.js | 22 or newer |
| OpenBao | 2.x with the Transit secrets engine enabled (tested with 2.7.2) |

HashiCorp Vault exposes a compatible Transit API and may work, but it is not
tested.

OpenBao cannot be the only KMS backend. Credo also needs `randomBytes` and
symmetric encryption, which a remote KMS cannot provide (see
[Limitations](#limitations)). Register Askar or the Node.js KMS alongside it.

## Installation

```bash
npm install @sovio-id/credo-openbao-kms
```

```bash
yarn add @sovio-id/credo-openbao-kms
```

```bash
bun add @sovio-id/credo-openbao-kms
```

The package is also published to JSR:

```bash
npx jsr add @sovio-id/credo-openbao-kms
```

npm releases are published from GitHub Actions with
[provenance](https://docs.npmjs.com/generating-provenance-statements).

## Quick start

Enable Transit in OpenBao:

```bash
bao secrets enable transit
# Optional: KV v2 storage for secp256k1 and X25519
bao secrets enable -path=secret kv-v2
```

Register the backend with Credo's `KeyManagementModule`:

```ts
import { Agent } from '@credo-ts/core'
import { KeyManagementModule } from '@credo-ts/core/kms'
import { agentDependencies, NodeInMemoryKeyManagementStorage, NodeKeyManagementService } from '@credo-ts/node'

import { AppRoleAuth, FetchOpenBaoClient, OpenBaoKeyManagementService } from '@sovio-id/credo-openbao-kms'

const auth = new AppRoleAuth({
  address: 'https://openbao.example.com:8200',
  roleId: process.env.OPENBAO_ROLE_ID!,
  secretIdFile: '/var/run/secrets/openbao/secret-id',
})

const openBao = new OpenBaoKeyManagementService({
  client: new FetchOpenBaoClient({
    address: 'https://openbao.example.com:8200',
    token: () => auth.getToken(),
  }),
  // Optional: store secp256k1 and X25519 in KV v2. Omit to leave those key
  // types to the other backend.
  kvMount: 'secret',
})

// Fail at startup if OpenBao is sealed or unreachable.
await openBao.assertHealthy()

const agent = new Agent({
  dependencies: agentDependencies,
  modules: {
    // ...your storage module (Askar or Drizzle)
    kms: new KeyManagementModule({
      backends: [
        openBao,
        // Handles randomBytes, encrypt/decrypt and symmetric keys.
        new NodeKeyManagementService(new NodeInMemoryKeyManagementStorage()),
      ],
      defaultBackend: 'openbao',
    }),
  },
})
```

Then use Credo's KMS API as usual:

```ts
const { keyId, publicJwk } = await agent.kms.createKey({
  type: { kty: 'EC', crv: 'P-256' },
})

const { signature } = await agent.kms.sign({ keyId, algorithm: 'ES256', data })
const { verified } = await agent.kms.verify({ key: { publicJwk }, algorithm: 'ES256', data, signature })
```

Notes:

- In production, back `NodeKeyManagementStorage` with your agent's storage
  instead of `NodeInMemoryKeyManagementStorage`, so local keys survive restarts.
  [`scripts/drizzleNodeKeyManagementStorage.ts`](scripts/drizzleNodeKeyManagementStorage.ts)
  shows one way to do that with `GenericRecord`s.
- On Node.js, import `@credo-ts/core` before `@credo-ts/core/kms` in the file
  your application loads first. The `kms` entry point does not load the
  `reflect-metadata` polyfill.
- To keep Askar as the default and use OpenBao only for selected keys, leave
  `defaultBackend` pointing at Askar and pass `backend: 'openbao'` when creating
  or importing those keys.

## Authentication

`FetchOpenBaoClient` takes a `token` that is either a string or a function
returning one. Use a function whenever the token can change.

**AppRole (recommended).** `AppRoleAuth` logs in, tracks the token lease, renews
it before expiry, and logs in again when renewal is no longer possible.
Concurrent requests share a single refresh, so a burst of signatures does not
cause a burst of logins.

```ts
const auth = new AppRoleAuth({
  address: 'https://openbao.example.com:8200',
  roleId: process.env.OPENBAO_ROLE_ID!,
  // Prefer a file mounted by your platform over an environment variable.
  secretIdFile: '/var/run/secrets/openbao/secret-id',
})

// After rotating the secret id on the server:
auth.setSecretId(newSecretId)
```

A reasonable starting point for the AppRole is `token_ttl=1h`,
`token_max_ttl=8h` and `bind_secret_id=true`.

**Static token.** `StaticTokenAuth` (or a plain string) is for local development
and tests only.

**Other auth methods.** Pass any function that returns a current token, for
example one backed by Kubernetes auth.

## Configuration

### `OpenBaoKeyManagementService`

| Option | Default | Description |
| --- | --- | --- |
| `client` | required | An `OpenBaoClient`, normally a `FetchOpenBaoClient`. |
| `deploymentId` | none | Isolates this deployment's keys from other deployments sharing the same OpenBao cluster. |
| `scopeResolver` | `<deploymentId>:<contextCorrelationId>` | Override how the isolation scope is derived from an agent context. |
| `keyNamePrefix` | `ac` | Prefix of generated Transit key names. |
| `publicKeyCacheTtlMs` | `300000` (5 min) | Public-key cache lifetime. `0` disables it. |
| `negativeCacheTtlMs` | `30000` (30 s) | How long a "key not found" result is cached, so keys owned by other backends do not cost a request on every lookup. `0` disables it. |
| `writeEnabled` | `true` | Set to `false` to stop creating, importing and deleting keys while still signing with existing ones. |
| `kvMount` | none | KV v2 mount for secp256k1 and X25519. Unset means those key types go to another backend. |
| `kvPathPrefix` | `credo-keys` | Path prefix inside `kvMount`. |

The backend registers under the name `openbao`.

### `FetchOpenBaoClient`

| Option | Default | Description |
| --- | --- | --- |
| `address` | required | OpenBao base URL, e.g. `https://openbao.example.com:8200`. |
| `token` | required | Token string, or a function returning one. |
| `mountPath` | `transit` | Mount path of the Transit engine. |
| `namespace` | none | Sent as `X-Vault-Namespace`. |
| `timeoutMs` | `10000` | Request timeout. |
| `fetch` | global `fetch` | Custom `fetch`, for tests or custom TLS. |

### `AppRoleAuth`

| Option | Default | Description |
| --- | --- | --- |
| `address` | required | OpenBao base URL. |
| `roleId` | required | AppRole role id. |
| `secretId` / `secretIdFile` | one required | The secret id, or a file to read it from. |
| `mountPath` | `approle` | AppRole auth mount path. |
| `namespace` | none | Sent as `X-Vault-Namespace`. |
| `timeoutMs` | `10000` | Request timeout. |
| `renewBeforeMs` | `30000` | Renew this long before the token expires. |
| `fetch` | global `fetch` | Custom `fetch`. |

## Supported key types and operations

| Key type | Stored in | Create | Import | Sign |
| --- | --- | --- | --- | --- |
| Ed25519 | Transit `ed25519` | yes | yes (BYOK) | `EdDSA` |
| P-256 / P-384 / P-521 | Transit `ecdsa-p256/384/521` | yes | yes (BYOK) | `ES256` / `ES384` / `ES512` |
| RSA 2048 / 3072 / 4096 | Transit `rsa-*` | yes | yes (BYOK) | `RS256/384/512`, `PS256/384/512` |
| secp256k1 | KV v2 (requires `kvMount`) | yes | yes | `ES256K`, signed in-process |
| X25519 | KV v2 (requires `kvMount`) | yes | yes | — (key agreement only) |
| Symmetric (`oct`) | not supported | — | — | — |

| Operation | Behaviour |
| --- | --- |
| `createKey`, `importKey`, `getPublicKey`, `deleteKey` | Supported for the key types above. |
| `sign` | Performed by Transit (secp256k1: in-process from the KV entry). |
| `verify` | Performed locally with public keys only. |
| `encrypt`, `decrypt` | Not supported; Credo routes them to another backend. |
| `randomBytes` | Not supported; Credo routes it to another backend. |

`isOperationSupported` returns `false` for anything this backend cannot do, so
Credo falls through to the next registered backend.

### DIDs

Keys held in OpenBao can back any DID method that obtains its keys through
Credo's KMS API. The test suite creates `did:key`, `did:jwk` and `did:peer`
(numAlgo 0) DIDs from OpenBao-held keys and resolves them back to the stored
public key. DID methods in extension packages work as long as they use Credo's
KMS rather than handling keys themselves.

## Importing existing keys

Issuers and holders often already have a key, for example the private key
behind an X.509 certificate issued by a CA. `importKey` accepts a private JWK in
the shape `node:crypto` and Credo produce:

```ts
import { X509KeyUsage, X509Service } from '@credo-ts/core'
import { PublicJwk } from '@credo-ts/core/kms'

const jwk = issuerPrivateKey.export({ format: 'jwk' })
const { keyId, publicJwk } = await agent.kms.importKey({ privateJwk: jwk })

// Issue a certificate whose signature is produced inside OpenBao.
const certificate = await X509Service.createCertificate(agentContext, {
  authorityKey: PublicJwk.fromUnknown(publicJwk),
  subjectPublicKey: PublicJwk.fromUnknown(holderPublicJwk),
  issuer: { commonName: 'Example Issuing CA' },
  subject: { commonName: 'Example Holder' },
  validity: { notBefore, notAfter },
  extensions: {
    basicConstraints: { ca: false },
    keyUsage: { usages: [X509KeyUsage.DigitalSignature] },
  },
})
```

For Transit key types, the backend builds the BYOK payload locally:

1. Export the private JWK as PKCS#8 DER.
2. Generate a random AES-256 key and wrap the PKCS#8 blob with it using AES Key
   Wrap with Padding (RFC 5649).
3. Wrap the AES key with Transit's RSA-4096 wrapping key using RSA-OAEP-SHA256.
4. Send the result to `transit/keys/:name/import` with `allow_rotation: false`.

Things to know:

- The private key is in the application's memory once, at import time. Import
  during provisioning and discard the source JWK.
- Imported keys cannot be rotated or exported.
- Importing a key under an existing key id throws `KeyManagementKeyExistsError`
  instead of overwriting.
- secp256k1 and X25519 imports are written to KV v2 and do not use the wrapping
  key (see [Security model](#security-model)).
- Verifiers do not need to import anything: certificate-chain validation and
  `verify` only use public keys.

## Key ids and multi-tenancy

Two identifiers are involved:

- **The Credo key id** is what DIDs, credential records and X.509 bindings
  store. Every key id issued by this backend starts with `ob_`
  (`OPENBAO_KEY_ID_PREFIX`); `openBaoKeyId(id)` adds the prefix idempotently.
  Always use the `keyId` returned by `createKey` or `importKey`.
- **The Transit key name** is what OpenBao sees:

```text
scope     = <deploymentId>:<contextCorrelationId>   (or just the context id)
scopeHash = sha256(scope).slice(0, 16)
name      = <keyNamePrefix>_<scopeHash>_<base64url(keyId)>
```

`contextCorrelationId` is `default` for the root agent and `tenant-<id>` for a
tenant. The hash keeps tenant ids out of OpenBao while giving every tenant
distinct key names, and the public-key cache is keyed the same way. Names longer
than 128 characters are shortened with a hash suffix.

The `ob_` prefix exists because Credo resolves a key id by asking each backend
in registration order, and Askar stores an imported JWK's `kid` verbatim.
Without a prefix, the same id could exist in both stores and the wrong one could
win.

Set `deploymentId` when several deployments share one OpenBao cluster.

## Operating in production

**Health checks.** `assertHealthy()` calls `sys/health` and throws
`OpenBaoSealedError` when the node is sealed and `OpenBaoUnreachableError` when
it cannot be reached. `health()` returns the raw status.

**Rolling back.** `writeEnabled: false` stops this backend from creating,
importing or deleting keys; existing keys keep signing, and new keys go to the
next backend. Pair it with a sign-only policy, because the flag is not an
authorization boundary. Do not unregister the backend while DIDs or credentials
still reference its keys.

**Removing a tenant.**

```ts
const deleted = await openBao.purgeScope(openBao.scopeForCorrelationId(`tenant-${tenantId}`))
// or: await openBao.purgeAgentContext(tenantAgentContext)
```

Purging lists Transit (and KV) keys page by page and deletes only those in the
given scope.

**Never rotate a Transit key that backs a DID, certificate or credential.**
Rotation changes the public key, and every existing signature and DID document
that references the key id stops verifying. Imported keys are created with
rotation disabled; deny rotation for generated keys in your policy.

**Seal and unseal.** OpenBao must be unsealed before it can sign.
[docs/seal.md](docs/seal.md) covers every OpenBao 2.7 seal option, how to choose
one, and initialisation, migration and disaster-recovery runbooks.

## OpenBao policy

A least-privilege policy for the agent, assuming Transit at `transit/` and the
optional KV fallback at `secret/` with the default `credo-keys` prefix:

```hcl
# Sign and read public keys
path "transit/sign/*"         { capabilities = ["update"] }
path "transit/keys/*"         { capabilities = ["create", "read", "update", "delete"] }

# Delete keys (deletion_allowed) and purge a tenant
path "transit/keys/*/config"  { capabilities = ["update"] }
path "transit/keys"           { capabilities = ["list"] }

# Import (BYOK)
path "transit/wrapping_key"   { capabilities = ["read"] }
path "transit/keys/*/import"  { capabilities = ["update"] }

# KV fallback for secp256k1 / X25519 (only with kvMount)
path "secret/data/credo-keys/*"     { capabilities = ["create", "read", "update"] }
path "secret/metadata/credo-keys/*" { capabilities = ["list", "delete"] }

# Never allow
path "transit/keys/*/rotate"  { capabilities = ["deny"] }
path "transit/export/*"       { capabilities = ["deny"] }
path "transit/backup/*"       { capabilities = ["deny"] }
```

Drop what you do not use. A sign-only role (for rollbacks, or when keys are
pre-provisioned) needs only `update` on `transit/sign/*`, `read` on
`transit/keys/*`, and `read` on the KV data path.

## Security model

- Private keys created in Transit never leave OpenBao. The agent sends only the
  data to sign.
- Imported Transit keys pass through the application once, then live only in
  OpenBao.
- **KV-backed keys are weaker.** secp256k1 and X25519 private keys are stored as
  JWKs in KV v2. OpenBao encrypts them at rest, but any client allowed to read
  the path can retrieve them, and secp256k1 signing loads the key into the
  application. Prefer Transit key types where you can.
- Verification uses public keys only.
- OpenBao audit devices can record every Transit operation.
- Use short-lived, renewable tokens (AppRole or Kubernetes auth), never a root
  token.

## Limitations

| Not supported | Why |
| --- | --- |
| `randomBytes` | Credo's API is synchronous; a remote KMS cannot satisfy it. |
| `encrypt` / `decrypt` | Transit's ciphertext format embeds a key version that Credo's API does not carry, and AES-CBC (used by DIDComm) is not a Transit key type. Use Askar or the Node.js KMS. |
| `HS256/384/512` | Possible through Transit HMAC, but verification would still need the key locally. |
| Symmetric (`oct`) keys | Only useful for encryption and HMAC, which this backend does not implement. |
| Native secp256k1 / X25519 | Transit has no such key types; the opt-in KV fallback covers them. |
| Key rotation | See [Operating in production](#operating-in-production). |

A remote KMS is also a poor fit for offline or mobile agents, and every `sign`
is a network round trip.

## Implementation notes

Details that matter if you work on the code or compare it with other KMS
backends:

- **ECDSA signatures** are requested with `marshaling_algorithm=jws`, which
  returns the raw `r || s` form JWA expects, so no DER conversion is needed.
- **RSA-PSS** uses `salt_length=hash`, as JWA requires (Transit defaults to the
  maximum salt length). RS* uses `signature_algorithm=pkcs1v15`.
- **Public keys** come back as raw base64 for Ed25519 and PEM for ECDSA/RSA;
  both are converted to JWK.
- **Verification is local** because Transit's `verify` is bound to a key
  version that Credo does not track.
- **Creating an existing Transit key is silent** in OpenBao, even with a
  different type. The backend compares the returned type and throws
  `KeyManagementKeyExistsError` on a mismatch.
- **Deleting** requires setting `deletion_allowed=true` first; `deleteKey` does
  both and returns `false` for an unknown key.
- **Public keys are cached** because Credo calls `getPublicKey` on each backend
  to route every `sign`; without the cache each signature would cost two round
  trips.
- **secp256k1** uses `@noble/curves` rather than `node:crypto`, because not
  every runtime's OpenSSL build includes the curve.

## Development

```bash
bun install
bun run ci          # format check, type check, unit tests, build
```

`bun test` runs the offline unit tests (RFC 5649 vectors, key-name mapping,
secp256k1). To test against a real server:

```bash
docker run -d --name openbao-dev -p 8200:8200 \
  -e BAO_DEV_ROOT_TOKEN_ID=root \
  -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  openbao/openbao:latest server -dev

bun run live-check
```

The live check runs a Credo agent with Drizzle/SQLite storage against OpenBao
and exercises every key type: create, import, sign and verify, `did:key`,
`did:jwk` and `did:peer` creation, X.509 CA and leaf issuance, deletion, and
routing of `randomBytes` and AES-GCM to the Node.js backend.

### Local stack and demo app

```bash
docker compose up -d --build
```

This starts OpenBao (PebbleDB storage, auto-initialised and unsealed), a Credo
agent with an HTTP API on port 3000, and a demo web app on
[http://localhost:3001](http://localhost:3001). The demo covers key management,
signing, DIDs, X.509, and SD-JWT VC and mdoc issuance and verification with
OpenBao-held keys. `docker compose down -v` removes everything.

**The Compose stack is for local development only.** It stores the root token
and unseal key in a volume readable by the agent, auto-unseals, and serves
OpenBao over plain HTTP with permissive CORS.

## Supply chain

The repository includes a CycloneDX 1.6 SBOM and a Cryptography Bill of
Materials (CBOM) in [`sbom/`](sbom), generated with `npm run bom`. See
[docs/bom.md](docs/bom.md).

## Contributing and security

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report
vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in
public issues.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).

This is a community project. It is not affiliated with, endorsed by, or
sponsored by the Credo maintainers, the OpenWallet Foundation, or the OpenBao
maintainers. "Credo" and "OpenBao" are used only to describe interoperability.
