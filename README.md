# credo-ts-openbao

An [OpenBao](https://openbao.org) Transit backend for Credo's key management
service (KMS), plus the feasibility findings behind it.

**Verdict: yes. OpenBao can hold and use every asymmetric key type Credo 0.7
supports.** Ed25519, P-256/P-384/P-521 and RSA 2048/3072/4096 are created,
imported and signed inside Transit. secp256k1 and X25519 — which Transit cannot
represent — are stored in an OpenBao KV v2 mount when `kvMount` is configured;
secp256k1 signatures are produced locally. OpenBao still cannot be the only
backend: Credo also needs local symmetric crypto and random bytes.

Everything below was verified against OpenBao **2.7.2** and Credo **0.7.4**.
Run `npm run live-check` to reproduce it (see [Running the check](#running-the-check)).

---

## How it plugs in

Credo's KMS is a small interface. A backend only implements what its key store
can do, and Credo routes every operation to a backend that returns `true` from
`isOperationSupported`:

```ts
import { Agent } from '@credo-ts/core'
import { KeyManagementModule } from '@credo-ts/core/kms'
import { NodeInMemoryKeyManagementStorage, NodeKeyManagementService } from '@credo-ts/node'

import { FetchOpenBaoClient, OpenBaoKeyManagementService } from 'credo-ts-openbao'

const openBao = new OpenBaoKeyManagementService({
  client: new FetchOpenBaoClient({
    address: 'https://openbao.internal:8200',
    // A function keeps working when the token is renewed by AppRole/Kubernetes auth
    token: async () => getTokenFromAuthMethod(),
  }),
  // Opt in to KV v2 storage for secp256k1 and X25519, which Transit cannot
  // represent. Omit this to route those key types to Node.js or Askar instead.
  kvMount: 'secret',
})

const agent = new Agent({
  dependencies: agentDependencies,
  modules: {
    storage, // Drizzle or Askar, see the Credo storage guide
    kms: new KeyManagementModule({
      backends: [
        openBao,
        // Handles randomBytes, encrypt/decrypt and symmetric keys
        new NodeKeyManagementService(new NodeInMemoryKeyManagementStorage()),
      ],
      // Every asymmetric key type Credo needs for DIDs is handled by OpenBao
      defaultBackend: 'openbao',
    }),
  },
})
```

For the Node.js fallback in production, back `NodeKeyManagementStorage` with the
agent's storage (a `GenericRecord`) instead of `NodeInMemoryKeyManagementStorage`,
so local keys survive restarts. The live check does exactly that with
Drizzle/SQLite.

Then everything goes through the normal API:

```ts
const { keyId, publicJwk } = await agent.kms.createKey({
  type: { kty: 'EC', crv: 'P-256' },
})

const { signature } = await agent.kms.sign({ keyId, algorithm: 'ES256', data })
const { verified } = await agent.kms.verify({ key: { publicJwk }, algorithm: 'ES256', data, signature })
```

On Node, import `@credo-ts/core` before `@credo-ts/core/kms` in the file your app
loads first: the `kms` entry point does not load the `reflect-metadata` polyfill.

---

## Why OpenBao KMS for Credo?

Credo's KMS interface is deliberately small: create, import, read, delete, sign,
verify, encrypt/decrypt and random bytes. OpenBao's Transit engine is a key-as-a-
service API that maps almost one-to-one onto the asymmetric half of that
interface, and it adds operational features a wallet or issuer deployment usually
needs anyway.

- **Private signing keys stay out of the agent process.** For Ed25519, P-256,
  P-384, P-521 and RSA, the key is generated inside Transit and never returns to
  the application. A compromised agent can request signatures, but it cannot read
  or export the key. Local KMS backends (including Askar) necessarily hold the
  private key in the process that stores it.
- **One key service for many agents and tenants.** Issuers, holders and verifiers
  can share a central OpenBao cluster instead of copying key files onto every
  agent. Namespaces, AppRole and Kubernetes auth make this practical for
  multi-tenant deployments.
- **Audit and policy are built in.** Every Transit operation can be recorded by an
  audit device, and a least-privilege policy can allow signing without allowing
  key creation or export. That is a much stronger story for compliance than
  "the key is in the agent's database".
- **Open source and Vault-compatible.** OpenBao is open source and speaks the
  Vault API, so existing Vault tooling, policies and operational knowledge carry
  over without a proprietary KMS dependency.
- **BYOK without sending plaintext.** Existing X.509 issuer/holder keys can be
  imported through Transit's BYOK endpoint using RSA-OAEP + AES-KWP, so the
  private key never crosses the network in the clear. See
  [Importing X.509 keys](#importing-x509-keys-issuers-holders-and-verifiers).
- **More signing coverage than a local Node wallet.** Transit signs RSA
  (RS/PS) and P-521, which Askar does not. That matters for X.509 chains and
  JOSE profiles that use RSA or P-521.
- **A clear split of responsibilities.** OpenBao handles asymmetric signing keys;
  Node.js or Askar handles `randomBytes`, symmetric encryption and DIDComm
  encryption. Each backend does what it is actually good at, and Credo routes
  between them automatically.

### When OpenBao is not the right fit

- **Offline or mobile agents.** A remote KMS is the wrong dependency for a phone
  that must work without network access.
- **DIDComm encryption.** Transit's encrypt/decrypt shape does not match Credo's
  versionless `iv`/`tag` API, and AES-CBC is not a Transit key type. Keep
  DIDComm's X25519/AES keys in Askar or the Node backend.
- **secp256k1/X25519-only deployments.** The KV fallback keeps the key in
  OpenBao, but signing for secp256k1 happens in-process and the KV entry is a
  plaintext JWK from the client's perspective. A local encrypted store may be a
  simpler and equally strong choice for those key types.
- **Synchronous hot paths.** Every `sign` is a network round trip. The public-key
  cache avoids a second round trip per signature, but a local KMS is faster.

---

## Key types and DID method coverage

Credo 0.7 represents every asymmetric key as a JWK. These are all the key types
Credo can put in a DID document or use for JOSE signing:

| Key type | Credo algorithms | OpenBao storage | Importable |
|---|---|---|---|
| Ed25519 | `EdDSA` | Transit `ed25519` | yes |
| P-256 | `ES256` | Transit `ecdsa-p256` | yes |
| P-384 | `ES384` | Transit `ecdsa-p384` | yes |
| P-521 | `ES512` | Transit `ecdsa-p521` | yes |
| RSA 2048/3072/4096 | `RS*`, `PS*` | Transit `rsa-*` | yes |
| secp256k1 | `ES256K` | KV v2 (`kvMount`) | yes |
| X25519 | key agreement only | KV v2 (`kvMount`) | yes |

Symmetric (`oct`) keys are not DID keys and are left to Node.js/Askar. Credo 0.7
does not expose a BLS key type.

The DID methods shipped in `@credo-ts/core` all work with keys imported into
OpenBao:

| DID method | Registrar | Key types used | Verified in the live check |
|---|---|---|---|
| `did:key` | yes | Ed25519, X25519, P-256/384/521, secp256k1 | Ed25519 |
| `did:jwk` | yes | any asymmetric JWK | secp256k1 (KV fallback) |
| `did:peer` | yes (numAlgo 0/1/2/4) | Ed25519, X25519, P-256/384/521, secp256k1 | numAlgo 0 with X25519 (KV fallback) |
| `did:web` | resolver only | any key used by services | not applicable |

DID methods in extension packages (`@credo-ts/webvh`, `@credo-ts/cheqd`,
`@credo-ts/hedera`, ...) call the same KMS API and use the same JWK key types. If
a method asks Credo's KMS for a key, this backend can create or import it. A
method that does ledger-specific key handling inside its own package remains
governed by that package.

The live check imports every key type, signs with each one that supports signing,
and creates a `did:key`, a `did:jwk` and a `did:peer` from imported key ids — so
the whole path from private JWK to DID document is exercised, not just the KMS
calls in isolation.

---

## Capability matrix

### Key types

| Credo key type | Store used by this backend | `createKey` | `importKey` | `sign` |
|---|---|---|---|---|
| Ed25519 | Transit `ed25519` | yes | yes (BYOK) | `EdDSA` |
| P-256 / P-384 / P-521 | Transit `ecdsa-*` | yes | yes (BYOK) | `ES256/384/512` |
| RSA 2048/3072/4096 | Transit `rsa-*` | yes | yes (BYOK) | `RS*` and `PS*` |
| secp256k1 | KV v2 (`kvMount`) | yes | yes | `ES256K`, signed locally |
| X25519 | KV v2 (`kvMount`) | yes | yes | — (key agreement only) |
| AES / HMAC (`oct`) | Node.js / Askar | no | no | no |

### Operations

| Credo operation | OpenBao Transit | This backend |
|---|---|---|
| `createKey` Ed25519, P-256/384/521, RSA 2048/3072/4096 | `ed25519`, `ecdsa-*`, `rsa-*` | yes |
| `createKey` secp256k1, X25519 | — | yes with `kvMount`; otherwise Node/Askar |
| `sign` EdDSA | `ed25519` | yes |
| `sign` ES256/384/512 | `ecdsa-*` with `marshaling_algorithm=jws` | yes |
| `sign` RS256/384/512, PS256/384/512 | `rsa-*` | yes |
| `sign` ES256K | — | yes with `kvMount`, using `@noble/curves` |
| `sign` HS256/384/512 | `hmac` endpoints | no (possible, but verify would need local HMAC) |
| `verify` all asymmetric types | — | yes, done locally (`node:crypto`, plus `@noble/curves` for secp256k1) |
| `getPublicKey` | `GET /keys/:name` or KV read | yes |
| `deleteKey` | `DELETE /keys/:name` or KV metadata delete | yes |
| `importKey` all asymmetric JWK types | BYOK `import` (Transit) or KV write | yes |
| `importKey` symmetric (`oct`) | — | no, Node/Askar |
| `encrypt` / `decrypt` | `encrypt`/`decrypt` | no, intentional (see below) |
| `randomBytes` | `transit/random` | no, **impossible** (see below) |

`isOperationSupported` returns `false` for the gaps, so Credo picks the next
backend automatically. Nothing throws `No key management service backend found`
as long as one other backend (Node or Askar) is registered. secp256k1 and X25519
are only claimed by this backend when `kvMount` is set.

---

## Findings that shaped the implementation

### 1. ECDSA needs no signature conversion

OpenBao returns ECDSA signatures ASN.1/DER encoded by default, while JWA wants
raw `r || s`. Credo's docs show a `derEcSignatureToRaw` helper for cloud KMSs.
Transit has a better option:

```json
{ "input": "...", "marshaling_algorithm": "jws" }
```

`marshaling_algorithm=jws` returns URL-safe base64 of the raw `r || s` form, so
it drops straight into ES256/ES384/ES512. Verified lengths: 64, 96 and 132 bytes.

### 2. RSA-PSS needs `salt_length=hash`

Transit defaults to the maximum PSS salt length; JWA (PS256/384/512) requires the
salt length to equal the hash length. Without `salt_length: "hash"` other JOSE
implementations can reject the signature. The backend sets it, and also picks
`signature_algorithm: pkcs1v15` for RS*.

### 3. Public keys come back in two different formats

`GET /transit/keys/:name` returns:

- Ed25519: `public_key` is **standard base64 of the raw 32 bytes**.
- ECDSA and RSA: `public_key` is **PEM (PKIX)**.

The backend converts both into a JWK (`createPublicKey(pem).export({ format: 'jwk' })`
or `{ kty: 'OKP', crv: 'Ed25519', x }`).

### 4. Verification is done locally, not through Transit

`POST /transit/verify/:name` is bound to a specific key **version**. Credo's
decrypt/verify API only carries the signature bytes, not a version, and Transit
rejects `v0` with `ciphertext or signature version is disallowed by policy`.
That breaks as soon as a key is rotated.

Verification only needs public material, so the backend verifies with
`node:crypto` using the public JWK (and `@noble/curves` for secp256k1, which not
every runtime's OpenSSL build supports). This also lets the backend verify keys
it does not hold — for example RSA keys in an X.509 certificate chain, which is a
common Credo failure on Node without an RSA-capable verifier.

### 5. Creating a key that already exists is silent — including type changes

`POST /transit/keys/:name` returns `200` with the **existing** key when the name
is taken, even if `type` differs. There is no error and no warning. The backend
compares the returned `type` with the requested one and throws
`KeyManagementKeyExistsError` on a mismatch.

### 6. Deleting needs `deletion_allowed`

Transit refuses `DELETE` unless the key was first configured with
`deletion_allowed=true`. `deleteKey` does the config call, then the delete, and
returns `false` for an unknown key.

### 7. `randomBytes` cannot be implemented by any remote KMS

Credo's signature is synchronous:

```ts
randomBytes(agentContext, options): Uint8Array
```

A remote call cannot satisfy it. This is the strongest argument that an
OpenBao-backed agent must still register a local backend. This backend returns
`false` from `isOperationSupported` and throws a descriptive error if called.

### 8. Encrypt/decrypt are a poor fit

Transit returns an opaque blob: `vault:v1:<base64(iv || ciphertext || tag)>`.
Credo's `decrypt` receives `iv`, `tag` and ciphertext as separate fields with no
key version, so rebuilding the blob means assuming the version (rotation breaks
it) or trying versions until authentication succeeds. AES-CBC, which DIDComm
uses, is not a Transit key type at all.

Recommendation: leave `encrypt`/`decrypt` to Askar (or the Node backend), and
use OpenBao for signing keys. DIDComm then keeps an X25519 key agreement key in
Askar while DIDs and credentials sign in OpenBao.

### 9. Rotation breaks the "one key id, one public key" assumption

Credo stores a `keyId` in DIDs and credential records and resolves its public
key through `getPublicKey(keyId)`. Rotating a Transit key creates a new version,
and `getPublicKey` then returns the new public key — so previously issued DIDs
and credentials no longer match the published key.

Until a version-pinning mechanism is added, **do not rotate Transit keys that
back Credo key ids**. Rotation is still fine for keys used outside Credo.

Keys created with `importKey` are imported with `allow_rotation: false`, so
Transit itself refuses to rotate them. That is deliberate: an imported key is
usually the private key behind an already-issued X.509 certificate, and rotating
it would silently break every certificate and credential that references it.

### 10. Transit cannot represent every key type Credo supports

Transit supports `ed25519`, `ecdsa-p256/384/521`, `rsa-2048/3072/4096`, AES,
ChaCha20 and HMAC. It does **not** support secp256k1 or X25519. Verified against
OpenBao 2.7.2:

```
POST /v1/transit/keys/probe {"type":"ecdsa-secp256k1"}
400 {"errors":["unknown key type ecdsa-secp256k1"]}

POST /v1/transit/keys/probe {"type":"x25519"}
400 {"errors":["unknown key type x25519"]}
```

Transit's `external-key` type is not a general-purpose escape hatch: it requires
the OpenBao server to be configured with an `ExternalKeyFactory` that knows how
to load the external key. It cannot be used by an application to import an
arbitrary secp256k1 or X25519 key over the API.

The default behaviour is therefore to leave these two key types to Node.js or
Askar. Setting `kvMount` opts into an OpenBao KV v2 fallback:

- The key pair is stored as a JSON record at
  `<kvMount>/data/credo-keys/<transit key name>`, with `keyType`, `privateJwk`
  and `publicJwk`.
- secp256k1 signing happens in-process with `@noble/curves`, a pure-JS
  implementation. `node:crypto` would work on Node.js but not on runtimes whose
  OpenSSL build lacks the curve (Bun, for example), so the backend uses
  `@noble/curves` consistently and produces the compact `r || s` JWA form. The
  private key is read from KV for each signature.
- X25519 is storage and public-key retrieval only. Credo 0.7's
  `KeyManagementService` has no key-agreement operation, so there is nothing
  else for this backend to implement.
- The KV fallback is **not** equivalent to Transit. There is no BYOK wrapping,
  no versioned signing and no server-side use of the key; the private JWK is
  visible to any client that can read the KV path. OpenBao still encrypts it at
  rest under the barrier, but the security model is closer to an encrypted
  database than to a KMS. Use Transit-backed key types where possible.

### 11. Every operation costs a public-key lookup

To pick the backend for a `sign`, Credo first calls `getPublicKey(keyId)` on each
backend. Without caching, every signature would be two HTTP round trips. The
backend caches public keys for 5 minutes (`publicKeyCacheTtlMs`, default
`5 * 60 * 1000`; set `0` to disable).

---

## Importing X.509 keys (issuers, holders and verifiers)

Issuers and holders usually do not generate their signing key inside the agent:
they already have an X.509 certificate and its private key, issued by a CA or by
an HSM. Credo's X.509 support signs certificates through the KMS, so for those
keys to be used the private key has to be importable.

`importKey` accepts a private JWK in exactly the shape `node:crypto` and Credo
produce (`KeyObject.export({ format: 'jwk' })`):

```ts
import { X509Service, X509KeyUsage } from '@credo-ts/core'
import { PublicJwk } from '@credo-ts/core/kms'

// The key that matches the issuer's existing X.509 certificate.
const jwk = issuerPrivateKey.export({ format: 'jwk' })

const { keyId, publicJwk } = await agent.kms.importKey({ privateJwk: jwk })

// Sign credentials with it...
const { signature } = await agent.kms.sign({ keyId, algorithm: 'ES256', data })

// ...or issue a certificate whose signature is produced by OpenBao.
const caPublicJwk = PublicJwk.fromUnknown(publicJwk)
const certificate = await X509Service.createCertificate(agentContext, {
  authorityKey: caPublicJwk, // signs with the OpenBao-held private key
  subjectPublicKey: PublicJwk.fromUnknown(holderPublicJwk),
  issuer: { commonName: 'Acme Issuing CA' },
  subject: { commonName: 'Credo Holder' },
  validity: { notBefore, notAfter },
  extensions: {
    basicConstraints: { ca: false },
    keyUsage: { usages: [X509KeyUsage.DigitalSignature] },
  },
})
```

A verifier needs no import at all. Certificate-chain validation only uses public
keys, and `verify` accepts a `publicJwk`, so the verifier can validate a chain
with the Node/Askar backend or with this one without holding any private key.

### How the private key reaches Transit

Transit's BYOK import never accepts plaintext key material on the wire. The
backend builds the payload locally:

```
base64( RSA-OAEP-SHA256(ephemeral AES-256 key) || AES-KWP(PKCS#8 DER) )
```

1. Export the private JWK as PKCS#8 DER.
2. Generate a random 32-byte AES key.
3. Wrap the PKCS#8 blob with that AES key using **AES Key Wrap with Padding**
   (RFC 5649).
4. Wrap the AES key with Transit's RSA-4096 wrapping key using RSA-OAEP/SHA-256
   (`GET /transit/wrapping_key`), always 512 bytes.
5. `POST /transit/keys/:name/import` with `allow_rotation: false`.

OpenBao never sees the plaintext private key and never returns it. It is stored
encrypted under OpenBao's barrier; `export` is not granted to the app policy.

Only Transit-supported key types use this envelope. secp256k1 and X25519 imports
are written to the KV v2 mount (when `kvMount` is set) instead; for secp256k1
the backend then signs locally. That path does not use the Transit wrapping key
and has the weaker security model described in
[finding 10](#10-transit-cannot-represent-every-key-type-credo-supports).

### Caveats

- **The key material passes through the application process once.** Unlike
  `createKey`, the private key exists in the agent's memory (as a JWK) before it
  is imported. Import only keys you are already prepared to handle in-process,
  do it once at provisioning time, and do not keep the source JWK around.
- **Import does not make a key exportable.** There is no `exportKey` in Credo's
  KMS interface, and the backend does not grant Transit `export`.
- **Imported keys cannot rotate** (see finding 9). If certificate renewal needs a
  new key, import it under a new key id.
- **A duplicate import throws `KeyManagementKeyExistsError`** rather than
  overwriting the existing key. Import under a new `kid` if you need a second
  copy.
- Public-only import (`public_key`) is supported by Transit and used for
  verifier-side entries, but Credo's `importKey` carries a private JWK, so the
  backend always imports the full pair.
- Import requires the app policy to allow `update` on `keys/*/import` and `read`
  on `keys/*` (plus `read` on `transit/wrapping_key`). The KV fallback needs
  `create`/`update` on `secret/data/credo-keys/*` and `delete`/`update` on
  `secret/metadata/credo-keys/*` instead.

---

## Security notes

- For Transit-backed keys created with `createKey`, private keys never leave
  OpenBao; the agent only sends data to sign. Imported Transit keys pass through
  the process once at provisioning time (see the X.509 section).
- **KV-backed keys are weaker.** For secp256k1 and X25519, the private JWK is
  stored in an OpenBao KV v2 entry. It is encrypted at rest by the barrier, but
  any client with `read` on that path can retrieve it, and secp256k1 signing
  brings it into the agent process. Use Transit key types when the stronger
  guarantee matters.
- Verification is local and uses public material only.
- OpenBao audit devices record every Transit operation, which is usually a
  compliance win over keys held in the application.
- Use a least-privilege policy. The app needs `update` on `sign/<name>` and
  `read` on `keys/<name>`. Import additionally needs `update` on
  `keys/*/import` and `read` on `transit/wrapping_key`. KV fallback keys need
  `create`/`update` on `secret/data/credo-keys/*` and `delete`/`update` on
  `secret/metadata/credo-keys/*`. Granting `create` on `keys/*` lets a
  compromised app create keys; pre-provision keys and deny `create` where
  possible. Never grant `export`.
- Prefer AppRole or Kubernetes auth with a renewable, short-TTL token. Pass a
  token provider function rather than a static root token.
- Transit's `external-key` type can front an HSM or another cloud KMS when the
  OpenBao server is configured with an `ExternalKeyFactory`, so key material can
  later move behind OpenBao without changing Credo. This backend does not
  configure that server-side path.

---

## Key id to Transit key name

Transit key names must start and end with a word character. UUIDs qualify, so
Credo's default key ids are used as the key name directly and remain readable in
OpenBao. Other ids (DID URLs, for example) are base64url encoded with a `credo-`
prefix.

There is a theoretical collision between a literal key id and an encoded one
(e.g. key id `credo-YWJj` vs. the encoded form of `abc`). Use
`useDirectKeyNames: false` to always encode if that matters.

---

## Running the check

```bash
docker run -d --name openbao-dev -p 8200:8200 \
  -e BAO_DEV_ROOT_TOKEN_ID=root \
  -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  openbao/openbao:latest server -dev

npm install
npm run typecheck
npm test
npm run live-check
```

`npm test` runs the offline unit tests with `node:test` (via `bun test`): the
RFC 5649 vectors, key-name mapping, and secp256k1 generation/signing/verification
including cross-checks against `node:crypto` where the runtime supports the curve.

`live-check` is runtime-independent and works under Bun (`npm run live-check`)
and Node (`npx tsx scripts/live-check.ts`). It starts a real Credo `Agent` with:

- `DrizzleStorageModule` on `better-sqlite3` SQLite, with the core SQLite
  migrations from `@credo-ts/drizzle-storage/migrations/core/sqlite` applied
  before the agent initializes;
- `OpenBaoKeyManagementService` with `kvMount: 'secret'`;
- `NodeKeyManagementService` backed by a `GenericRecord`-based
  `NodeKeyManagementStorage`, so local keys live in the same SQLite database as
  DIDs and credentials.

It then checks:

- routing: all seven asymmetric key types and `ES256K` go to OpenBao;
  `randomBytes` does not;
- create/sign/verify for Ed25519, P-256, P-384, P-521, RSA-2048 (RS256 and
  PS256), secp256k1 (ES256K) and X25519: correct store (Transit vs KV), public key
  readable, signature verifies by `keyId` and by `publicJwk`, tampered data is
  rejected;
- RSA-2048/3072/4096 are all created in Transit;
- `importKey` for every key type: public key matches the source key, the key
  lands in the expected store, and signing/verification works (except X25519,
  which is key agreement only); duplicate imports throw
  `KeyManagementKeyExistsError`;
- `did:key`, `did:jwk` and `did:peer` are created from imported key ids,
  resolve to the imported public key, and their `DidRecord`s are persisted
  through Drizzle;
- X.509: a self-signed CA and a leaf certificate are created with
  `X509Service.createCertificate`, both signatures are produced by keys held in
  OpenBao, the CA verifies the leaf, and a credential signed by the leaf key
  verifies against the certificate's public key;
- lifecycle: create, public key read, delete, delete of an unknown key, and
  deletion of both Transit-backed and KV-backed keys;
- the Node.js backend persists its private keys as `GenericRecord`s in SQLite
  and still handles `randomBytes` and AES-GCM encrypt/decrypt.

The SQLite file is created in a temporary directory and removed on exit. For a
persistent database, apply the core migrations once with `drizzle-kit` (or the
package's migration CLI) instead of replaying them on every start.

---

## Not implemented (and why)

| Feature | Effort | Note |
|---|---|---|
| `encrypt` / `decrypt` | medium, fragile | Needs version recovery and only covers AES-GCM/ChaCha20. Askar is the better home. |
| `HS256/384/512` | low | Map to `/transit/hmac`; verifying with a public JWK would still need local HMAC. |
| `randomBytes` | impossible | Synchronous Credo API vs. remote service. |
| Native Transit secp256k1, X25519 | impossible | Transit has no such key types. The opt-in KV fallback covers them instead. |
| Symmetric import (`oct`) | low | Not a DID key type and only useful for encrypt/HMAC, which this backend does not implement. |

---

## Files

```
src/OpenBaoClient.ts                 fetch client for Transit plus the KV v2 fallback endpoints
src/OpenBaoKeyManagementService.ts   the KeyManagementService implementation
src/aesKeyWrap.ts                    RFC 5649 AES-KWP, implemented over AES-ECB
src/secp256k1.ts                     secp256k1 key generation/sign/verify via @noble/curves
src/transitImport.ts                 JWK -> PKCS#8, public JWK derivation, BYOK wrapping
src/index.ts                         package exports
scripts/live-check.ts                Drizzle/SQLite agent against a live OpenBao
```

Licensed under Apache-2.0, matching Credo.
