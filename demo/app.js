const STORAGE_KEY = 'credo-openbao-demo.keys.v1'
const MAX_ACTIVITY = 120

const $ = (selector, root = document) => root.querySelector(selector)
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)]

const state = {
  info: null,
  keys: loadKeys(),
  lastSignature: null,
  lastCipher: null,
  activity: [],
}

function loadKeys() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]')
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function saveKeys() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state.keys))
}

function esc(value) {
  return String(value ?? '').replace(
    /[&<>"']/g,
    (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character],
  )
}

function shortKeyId(keyId) {
  return keyId.length > 30 ? `${keyId.slice(0, 15)}…${keyId.slice(-10)}` : keyId
}

function storeLabel(store) {
  return store === 'transit' ? 'Transit' : store === 'kv' ? 'KV v2' : store === 'node' ? 'Node.js' : 'unknown'
}

function storeBadge(store) {
  const className = store === 'transit' ? 'ok' : store === 'kv' ? 'violet' : store === 'node' ? 'blue' : 'neutral'
  return `<span class="badge ${className}">${esc(storeLabel(store))}</span>`
}

function toast(kind, title, message) {
  const container = $('#toasts')
  const element = document.createElement('div')
  element.className = `toast ${kind}`
  element.innerHTML = `<strong>${esc(kind === 'ok' ? 'OK' : 'Error')}</strong><div><div>${esc(title)}</div><div class="muted">${esc(message)}</div></div>`
  container.append(element)
  setTimeout(() => element.remove(), 5200)
}

function setBusy(button, busy, label) {
  if (!button) return
  if (busy) {
    if (!button.dataset.label) button.dataset.label = button.textContent
    button.disabled = true
    if (label) button.textContent = label
  } else {
    button.disabled = false
    if (button.dataset.label) {
      button.textContent = button.dataset.label
      delete button.dataset.label
    }
  }
}

function logRequest(method, path, status, ms) {
  state.activity.unshift({
    time: new Date().toLocaleTimeString(),
    method,
    path,
    status,
    ms: Math.round(ms),
  })
  if (state.activity.length > MAX_ACTIVITY) state.activity.length = MAX_ACTIVITY
  renderActivity()
}

async function api(path, { method = 'GET', body } = {}) {
  const started = performance.now()
  let status = 0

  try {
    const response = await fetch(`/api${path}`, {
      method,
      ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
    })
    status = response.status
    const text = await response.text()
    let payload = null
    if (text) {
      try {
        payload = JSON.parse(text)
      } catch {
        payload = text
      }
    }

    logRequest(method, `/api${path}`, status, performance.now() - started)
    if (!response.ok) throw new Error(payload?.error ?? `${response.status} ${response.statusText}`)
    return payload
  } catch (error) {
    if (!status) logRequest(method, `/api${path}`, 'ERR', performance.now() - started)
    throw error
  }
}

/* -------------------------------------------------------------------------- */
/* Navigation                                                                  */
/* -------------------------------------------------------------------------- */

function switchView(view) {
  $$('.view').forEach((section) => section.classList.toggle('active', section.id === `view-${view}`))
  $$('.nav-link').forEach((button) => button.classList.toggle('active', button.dataset.view === view))
  window.scrollTo({ top: 0, behavior: 'smooth' })
  if (view === 'dids') void loadDids()
}

function wireNavigation() {
  $$('.nav-link').forEach((button) => {
    button.addEventListener('click', () => switchView(button.dataset.view))
  })
  $$('[data-goto]').forEach((button) => {
    button.addEventListener('click', () => switchView(button.dataset.goto))
  })
}

/* -------------------------------------------------------------------------- */
/* Overview                                                                    */
/* -------------------------------------------------------------------------- */

async function loadInfo() {
  const button = $('#refresh-info')
  setBusy(button, true, 'Refreshing…')
  try {
    state.info = await api('/info')
    renderInfo()
    populateKeyTypes()
    toast('ok', 'Connected', `OpenBao ${state.info.openbao.status.version ?? ''} at ${state.info.openbao.address}`)
  } catch (error) {
    renderInfoError(error)
    toast('err', 'Could not load status', error.message)
  } finally {
    setBusy(button, false)
  }
}

function renderInfo() {
  const { openbao, storage, kms, environment } = state.info
  const status = openbao.status
  const openBaoPill = $('#pill-openbao')

  if (!status.reachable) {
    openBaoPill.className = 'pill err'
    openBaoPill.textContent = 'OpenBao unreachable'
  } else if (status.sealed) {
    openBaoPill.className = 'pill warn'
    openBaoPill.textContent = 'OpenBao sealed'
  } else {
    openBaoPill.className = 'pill ok'
    openBaoPill.textContent = `OpenBao ${status.version ?? ''} unsealed`
  }

  $('#pill-storage').textContent = `${storage.type} storage`
  $('#pill-backend').textContent = `${kms.defaultBackend} default · ${kms.backends.join(' + ')} fallback`
  $('#info-updated').textContent = `Updated ${new Date().toLocaleTimeString()}`

  $('#system-status').innerHTML = [
    row('Environment', environment),
    row('OpenBao address', openbao.address),
    row(
      'OpenBao health',
      !status.reachable
        ? `unreachable${status.error ? ` — ${status.error}` : ''}`
        : `${status.sealed ? 'sealed' : 'unsealed'} · initialized=${status.initialized} · HTTP ${status.httpStatus}`,
    ),
    row('OpenBao version', status.version ?? 'unknown'),
    row('KV v2 mount', openbao.kvMount),
    row('Agent storage', `${storage.type} — ${storage.path}`),
    row('KMS backends', kms.backends.join(', ')),
    row('Default backend', kms.defaultBackend),
  ].join('')

  $('#capabilities').innerHTML = Object.entries(kms.operations)
    .map(
      ([operation, backends]) => `
        <div class="capability">
          <span class="capability-name">${esc(operation)}</span>
          <span class="capability-backends">${
            backends.length
              ? backends
                  .map(
                    (backend) => `<span class="badge ${backend === 'openbao' ? 'ok' : 'blue'}">${esc(backend)}</span>`,
                  )
                  .join('')
              : '<span class="badge err">not supported</span>'
          }</span>
        </div>`,
    )
    .join('')

  const catalogBody = $('#catalog-table tbody')
  catalogBody.innerHTML = state.info.keyTypes
    .map(
      (keyType) => `
        <tr>
          <td><strong>${esc(keyType.label)}</strong></td>
          <td>${storeBadge(keyType.store)}</td>
          <td class="mono">${keyType.algorithms.length ? keyType.algorithms.map(esc).join(', ') : '—'}</td>
          <td class="mono">${keyType.dids.length ? keyType.dids.map(esc).join(', ') : '—'}</td>
          <td>${esc(keyType.note)}</td>
        </tr>`,
    )
    .join('')
}

function row(label, value) {
  return `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`
}

function renderInfoError(error) {
  $('#pill-openbao').className = 'pill err'
  $('#pill-openbao').textContent = 'Backend unreachable'
  $('#info-updated').textContent = 'Load failed'
  $('#system-status').innerHTML = row('Error', error.message)
  $('#capabilities').innerHTML = '<span class="badge err">Could not load capabilities</span>'
  $('#catalog-table tbody').innerHTML = `<tr><td colspan="5" class="muted">${esc(error.message)}</td></tr>`
}

function populateKeyTypes() {
  if (!state.info) return
  $('#key-type').innerHTML = state.info.keyTypes
    .map(
      (keyType) =>
        `<option value="${esc(keyType.id)}">${esc(keyType.label)} — ${esc(storeLabel(keyType.store))}</option>`,
    )
    .join('')
  updateKeyTypeHint()
}

function selectedCatalog() {
  if (!state.info) return null
  return state.info.keyTypes.find((keyType) => keyType.id === $('#key-type').value) ?? state.info.keyTypes[0]
}

function updateKeyTypeHint() {
  const keyType = selectedCatalog()
  if (!keyType) return
  $('#key-type-hint').innerHTML =
    `${esc(keyType.note)} &nbsp;·&nbsp; <strong>${esc(storeLabel(keyType.store))}</strong> · ${
      keyType.algorithms.length
        ? keyType.algorithms.map((algorithm) => `<code>${esc(algorithm)}</code>`).join(' ')
        : 'no signing'
    }`
}

/* -------------------------------------------------------------------------- */
/* Keys                                                                        */
/* -------------------------------------------------------------------------- */

function addKeyRecord(result, keyType, source) {
  const record = {
    keyId: result.keyId,
    typeId: keyType.id,
    label: keyType.label,
    store: result.store ?? keyType.store,
    algorithms: keyType.algorithms,
    signing: keyType.signing,
    dids: keyType.dids,
    source,
    createdAt: new Date().toISOString(),
    publicJwk: result.publicJwk,
  }
  state.keys = [record, ...state.keys.filter((key) => key.keyId !== result.keyId)]
  saveKeys()
}

function renderKeys() {
  const body = $('#keys-table tbody')

  if (state.keys.length === 0) {
    body.innerHTML = `<tr><td colspan="5" class="muted">No keys tracked yet. Generate one above, or import a sample JWK.</td></tr>`
  } else {
    body.innerHTML = state.keys
      .map(
        (key) => `
          <tr>
            <td>
              <div class="key-name">
                <strong>${esc(key.label)}</strong>
                <code title="${esc(key.keyId)}">${esc(shortKeyId(key.keyId))}</code>
              </div>
            </td>
            <td>${storeBadge(key.store)}</td>
            <td class="mono">${key.algorithms.length ? key.algorithms.map(esc).join(', ') : '—'}</td>
            <td><span class="badge neutral">${esc(key.source)}</span></td>
            <td>
              <div class="actions">
                ${key.signing ? `<button class="btn ghost small" data-action="sign" data-key-id="${esc(key.keyId)}">Sign</button>` : ''}
                ${key.dids.length ? `<button class="btn ghost small" data-action="did" data-key-id="${esc(key.keyId)}">DID</button>` : ''}
                <button class="btn ghost small" data-action="inspect" data-key-id="${esc(key.keyId)}">Inspect</button>
                <button class="btn danger small" data-action="delete" data-key-id="${esc(key.keyId)}">Delete</button>
              </div>
            </td>
          </tr>`,
      )
      .join('')
  }

  $('#clear-keys').disabled = state.keys.length === 0
  refreshKeySelects()
}

function refreshKeySelects() {
  const signSelect = $('#sign-key')
  const didSelect = $('#did-key')
  const options = state.keys.length
    ? state.keys
        .map((key) => `<option value="${esc(key.keyId)}">${esc(key.label)} · ${esc(shortKeyId(key.keyId))}</option>`)
        .join('')
    : '<option value="">No keys — create one first</option>'

  for (const select of [signSelect, didSelect]) {
    const previous = select.value
    select.innerHTML = options
    if (previous && state.keys.some((key) => key.keyId === previous)) select.value = previous
  }

  updateSignAlgorithms()
}

async function createKeyFor(keyType, importSample) {
  const keyId = $('#key-id').value.trim()

  if (importSample) {
    const sample = await api(`/demo/jwk?type=${encodeURIComponent(keyType.id)}`)
    return api('/keys/import', {
      method: 'POST',
      body: { privateJwk: sample.privateJwk, ...(keyId ? { keyId } : {}) },
    })
  }

  return api('/keys', {
    method: 'POST',
    body: {
      type: keyType.type,
      ...(keyId ? { keyId } : {}),
      ...(keyType.store === 'node' ? { backend: 'node' } : {}),
    },
  })
}

async function handleCreate(importSample) {
  const keyType = selectedCatalog()
  if (!keyType) {
    toast('err', 'Not ready', 'Wait for the status check to finish, then try again.')
    return
  }

  const button = importSample ? $('#import-key') : $('#create-key')
  setBusy(button, true, importSample ? 'Importing…' : 'Generating…')

  try {
    const result = await createKeyFor(keyType, importSample)
    addKeyRecord(result, keyType, importSample ? 'imported' : 'generated')
    renderKeys()
    $('#key-id').value = ''
    toast('ok', importSample ? 'Key imported' : 'Key created', `${keyType.label} · ${result.keyId}`)
  } catch (error) {
    toast('err', 'Key operation failed', error.message)
  } finally {
    setBusy(button, false)
  }
}

async function handleCreateAll() {
  if (!state.info) {
    toast('err', 'Not ready', 'Wait for the status check to finish, then try again.')
    return
  }

  const button = $('#create-all')
  const catalog = state.info.keyTypes
  const failures = []

  setBusy(button, true, `Creating 0/${catalog.length}…`)

  for (const [index, keyType] of catalog.entries()) {
    button.textContent = `Creating ${index + 1}/${catalog.length}…`
    try {
      const result = await createKeyFor(keyType, false)
      addKeyRecord(result, keyType, 'generated')
      renderKeys()
    } catch (error) {
      failures.push(`${keyType.label}: ${error.message}`)
    }
  }

  setBusy(button, false)

  if (failures.length === 0) {
    toast('ok', 'All key types created', `${catalog.length} keys added · ${state.keys.length} tracked in this browser`)
  } else {
    toast('err', `${failures.length} key type(s) failed`, failures[0])
  }
}

async function handleKeyAction(action, keyId) {
  const key = state.keys.find((candidate) => candidate.keyId === keyId)
  if (!key) return

  if (action === 'inspect') {
    try {
      const result = await api(`/keys/${encodeURIComponent(keyId)}`)
      showJson(`Key ${shortKeyId(keyId)}`, result)
    } catch (error) {
      toast('err', 'Inspect failed', error.message)
    }
    return
  }

  if (action === 'sign') {
    $('#sign-key').value = keyId
    updateSignAlgorithms()
    switchView('sign')
    return
  }

  if (action === 'did') {
    $('#did-key').value = keyId
    switchView('dids')
    return
  }

  if (action === 'delete') {
    if (!confirm(`Delete key ${keyId}?\n\nThis removes it from ${storeLabel(key.store)} and cannot be undone.`)) return

    try {
      const backend = key.store === 'node' ? 'node' : 'openbao'
      await api(`/keys/${encodeURIComponent(keyId)}?backend=${backend}`, { method: 'DELETE' })
      state.keys = state.keys.filter((candidate) => candidate.keyId !== keyId)
      saveKeys()
      renderKeys()
      toast('ok', 'Key deleted', `${key.label} · ${keyId}`)
    } catch (error) {
      toast('err', 'Delete failed', error.message)
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Sign & verify                                                               */
/* -------------------------------------------------------------------------- */

function updateSignAlgorithms() {
  const select = $('#sign-algorithm')
  const key = state.keys.find((candidate) => candidate.keyId === $('#sign-key').value)
  const algorithms = key?.algorithms ?? []

  select.innerHTML = algorithms.length
    ? algorithms.map((algorithm) => `<option value="${esc(algorithm)}">${esc(algorithm)}</option>`).join('')
    : '<option value="">No signing algorithm</option>'

  const disabled = algorithms.length === 0
  $('#do-sign').disabled = disabled
  $('#do-verify').disabled = disabled || !state.lastSignature
}

async function handleSign() {
  const keyId = $('#sign-key').value
  const algorithm = $('#sign-algorithm').value
  const data = $('#sign-data').value

  if (!keyId || !algorithm) {
    toast('err', 'Nothing to sign', 'Create a signing key first.')
    return
  }

  const button = $('#do-sign')
  setBusy(button, true, 'Signing…')

  try {
    const result = await api('/sign', { method: 'POST', body: { keyId, algorithm, data } })
    state.lastSignature = result

    $('#sign-signature').value = result.signature
    $('#sign-status').className = 'badge ok'
    $('#sign-status').textContent = 'Signed'
    const key = state.keys.find((candidate) => candidate.keyId === keyId)
    $('#sign-meta').innerHTML = [
      kvRow('Key', `${key?.label ?? 'key'} · ${shortKeyId(keyId)}`),
      kvRow('Algorithm', algorithm),
      kvRow('Backend', key?.store === 'node' ? 'node' : key?.store === 'kv' ? 'openbao (KV v2)' : 'openbao (Transit)'),
      kvRow('Payload', data),
    ].join('')

    await verifyCurrentSignature(true)
    toast('ok', 'Signature created', `${algorithm} signature returned as base64url`)
  } catch (error) {
    $('#sign-status').className = 'badge err'
    $('#sign-status').textContent = 'Failed'
    toast('err', 'Signing failed', error.message)
  } finally {
    setBusy(button, false)
    updateSignAlgorithms()
  }
}

async function verifyCurrentSignature(automatic = false) {
  if (!state.lastSignature) {
    toast('err', 'Nothing to verify', 'Sign a payload first.')
    return
  }

  try {
    const result = await api('/verify', {
      method: 'POST',
      body: {
        keyId: state.lastSignature.keyId,
        algorithm: state.lastSignature.algorithm,
        data: state.lastSignature.data,
        signature: state.lastSignature.signature,
      },
    })

    $('#verify-result').innerHTML = result.verified
      ? '<div class="verify-banner ok"><span>✓</span><span>Signature verified against the public key.</span></div>'
      : '<div class="verify-banner err"><span>✕</span><span>Signature did <strong>not</strong> verify.</span></div>'

    if (!automatic) {
      toast(result.verified ? 'ok' : 'err', result.verified ? 'Verified' : 'Not verified', 'Credo KMS verify()')
    }
  } catch (error) {
    $('#verify-result').innerHTML =
      `<div class="verify-banner err"><span>✕</span><span>${esc(error.message)}</span></div>`
    toast('err', 'Verification failed', error.message)
  }
}

function kvRow(label, value) {
  return `<div class="kv-row"><span>${esc(label)}</span><span>${esc(value)}</span></div>`
}

/* -------------------------------------------------------------------------- */
/* Random & symmetric crypto                                                   */
/* -------------------------------------------------------------------------- */

async function generateRandomBytes() {
  const button = $('#do-random')
  const length = Number($('#random-length').value)
  setBusy(button, true, 'Generating…')

  try {
    const result = await api('/random-bytes', { method: 'POST', body: { length } })
    $('#random-result').innerHTML = [
      kvRow('Backend', result.backend),
      kvRow('Length', `${result.length} bytes`),
      kvRow('base64url', result.base64url),
      kvRow('hex', result.hex),
    ].join('')
  } catch (error) {
    toast('err', 'randomBytes failed', error.message)
  } finally {
    setBusy(button, false)
  }
}

async function encryptData() {
  const button = $('#do-encrypt')
  const data = $('#crypto-plaintext').value
  setBusy(button, true, 'Encrypting…')

  try {
    const result = await api('/crypto/encrypt', { method: 'POST', body: { data } })
    state.lastCipher = result
    $('#do-decrypt').disabled = false
    $('#crypto-result').innerHTML = [
      kvRow('Backend', result.backend),
      kvRow('AES key', `${result.keyId}${result.keyCreated ? ' (created for this message)' : ''}`),
      kvRow('Algorithm', result.algorithm),
      kvRow('IV', result.iv),
      kvRow('Auth tag', result.tag),
      kvRow('Ciphertext', result.encrypted),
    ].join('')
    toast('ok', 'Encrypted', 'A256GCM via the Node.js KMS backend')
  } catch (error) {
    toast('err', 'Encryption failed', error.message)
  } finally {
    setBusy(button, false)
  }
}

async function decryptData() {
  if (!state.lastCipher) return
  const button = $('#do-decrypt')
  setBusy(button, true, 'Decrypting…')

  try {
    const result = await api('/crypto/decrypt', {
      method: 'POST',
      body: {
        keyId: state.lastCipher.keyId,
        iv: state.lastCipher.iv,
        tag: state.lastCipher.tag,
        encrypted: state.lastCipher.encrypted,
      },
    })
    $('#crypto-result').innerHTML = [
      kvRow('AES key', result.keyId),
      kvRow('Decrypted', result.data),
      kvRow('base64url', result.base64url),
      kvRow('Result', 'round trip matches the input'),
    ].join('')
    toast('ok', 'Decrypted', result.data)
  } catch (error) {
    toast('err', 'Decryption failed', error.message)
  } finally {
    setBusy(button, false)
  }
}

/* -------------------------------------------------------------------------- */
/* DIDs                                                                        */
/* -------------------------------------------------------------------------- */

async function loadDids() {
  const body = $('#dids-table tbody')

  try {
    const records = await api('/dids')
    body.innerHTML = records.length
      ? records
          .map(
            (record) => `
              <tr>
                <td class="mono">${esc(record.did)}</td>
                <td>${esc(record.role ?? '—')}</td>
                <td class="mono">${esc(JSON.stringify(record.keys ?? []))}</td>
              </tr>`,
          )
          .join('')
      : '<tr><td colspan="3" class="muted">No DIDs yet. Create one above.</td></tr>'
  } catch (error) {
    body.innerHTML = `<tr><td colspan="3" class="muted">${esc(error.message)}</td></tr>`
  }
}

async function createDid() {
  const keyId = $('#did-key').value
  const method = $('#did-method').value

  if (!keyId) {
    toast('err', 'No key selected', 'Create a key first.')
    return
  }

  const button = $('#do-create-did')
  setBusy(button, true, 'Creating…')

  try {
    const result = await api('/dids', { method: 'POST', body: { method, keyId } })
    $('#did-result').innerHTML = `<pre>${esc(JSON.stringify(result, null, 2))}</pre>`
    toast('ok', 'DID created', result.did ?? result.state ?? 'See the DID document')
    await loadDids()
  } catch (error) {
    toast('err', 'DID creation failed', error.message)
  } finally {
    setBusy(button, false)
  }
}

/* -------------------------------------------------------------------------- */
/* X.509                                                                       */
/* -------------------------------------------------------------------------- */

const X509_CHECK_LABELS = {
  caSelfSigned: 'CA certificate is self-signed and verifies',
  leafSignedByCa: 'Leaf certificate is signed by the CA key in OpenBao',
  leafBindsImportedKeyId: 'Leaf certificate binds the imported key id',
  chainValid: 'Certificate chain validates against the trusted CA',
  credentialSignatureVerified: 'Credential payload verifies against the certificate key',
}

async function runX509Demo() {
  const button = $('#run-x509')
  setBusy(button, true, 'Issuing certificates…')

  try {
    const result = await api('/x509/demo', { method: 'POST', body: {} })
    renderX509(result)

    const p256 = state.info?.keyTypes.find((keyType) => keyType.id === 'p256')
    if (p256) {
      addKeyRecord({ keyId: result.ca.keyId, store: 'transit' }, p256, 'x509 CA')
      addKeyRecord({ keyId: result.leaf.keyId, store: 'transit' }, p256, 'x509 leaf')
      renderKeys()
    }

    const passed = Object.values(result.checks).filter(Boolean).length
    toast(
      passed === Object.keys(result.checks).length ? 'ok' : 'err',
      'X.509 demo finished',
      `${passed}/${Object.keys(result.checks).length} checks passed`,
    )
  } catch (error) {
    toast('err', 'X.509 demo failed', error.message)
  } finally {
    setBusy(button, false)
  }
}

function renderX509(result) {
  $('#x509-checks').innerHTML = Object.entries(result.checks)
    .map(
      ([name, passed]) => `
        <div class="check ${passed ? 'ok' : 'err'}">
          <span class="dot">${passed ? '✓' : '✕'}</span>
          <span>${esc(X509_CHECK_LABELS[name] ?? name)}</span>
          <code>${esc(name)}</code>
        </div>`,
    )
    .join('')

  $('#x509-certs').hidden = false
  $('#x509-ca-meta').innerHTML = [
    kvRow('Key id', result.ca.keyId),
    kvRow('Subject', result.ca.subject),
    kvRow('Issuer', result.ca.issuer),
    kvRow('Serial', result.ca.serialNumber),
    kvRow('Valid until', new Date(result.ca.notAfter).toLocaleString()),
    kvRow('Thumbprint', result.ca.thumbprint),
  ].join('')
  $('#x509-ca-pem').textContent = result.ca.pem

  $('#x509-leaf-meta').innerHTML = [
    kvRow('Key id', result.leaf.keyId),
    kvRow('Subject', result.leaf.subject),
    kvRow('Issuer', result.leaf.issuer),
    kvRow('Serial', result.leaf.serialNumber),
    kvRow('Valid until', new Date(result.leaf.notAfter).toLocaleString()),
    kvRow('Thumbprint', result.leaf.thumbprint),
  ].join('')
  $('#x509-leaf-pem').textContent = result.leaf.pem

  $('#x509-credential-card').hidden = false
  $('#x509-credential').innerHTML = [
    kvRow('Payload', result.credential.payload),
    kvRow('Signature', result.credential.signature),
  ].join('')
}

/* -------------------------------------------------------------------------- */
/* Activity, dialog, clipboard                                                 */
/* -------------------------------------------------------------------------- */

function renderActivity() {
  const count = $('#activity-count')
  count.textContent = String(state.activity.length)

  const body = $('#activity-table tbody')
  if (!body) return

  body.innerHTML = state.activity.length
    ? state.activity
        .map(
          (entry) => `
            <tr>
              <td class="mono">${esc(entry.time)}</td>
              <td><span class="badge neutral">${esc(entry.method)}</span></td>
              <td class="mono">${esc(entry.path)}</td>
              <td><span class="badge ${
                entry.status === 'ERR' || Number(entry.status) >= 400 ? 'err' : 'ok'
              }">${esc(entry.status)}</span></td>
              <td class="mono">${esc(entry.ms)} ms</td>
            </tr>`,
        )
        .join('')
    : '<tr><td colspan="5" class="muted">No requests yet.</td></tr>'
}

function showJson(title, value) {
  $('#json-dialog-title').textContent = title
  $('#json-dialog-body').textContent = JSON.stringify(value, null, 2)
  $('#json-dialog').showModal()
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    toast('ok', 'Copied', 'Copied to the clipboard')
  } catch {
    toast('err', 'Copy failed', 'The browser blocked clipboard access')
  }
}

/* -------------------------------------------------------------------------- */
/* Wiring                                                                      */
/* -------------------------------------------------------------------------- */

function wire() {
  wireNavigation()

  $('#refresh-info').addEventListener('click', () => void loadInfo())

  $('#key-type').addEventListener('change', updateKeyTypeHint)
  $('#create-key').addEventListener('click', () => void handleCreate(false))
  $('#import-key').addEventListener('click', () => void handleCreate(true))
  $('#create-all').addEventListener('click', () => void handleCreateAll())

  $('#clear-keys').addEventListener('click', () => {
    if (!confirm('Forget all tracked keys in this browser? Keys are not deleted from OpenBao.')) return
    state.keys = []
    saveKeys()
    renderKeys()
    toast('ok', 'Local list cleared', 'Keys remain in OpenBao and SQLite')
  })

  $('#keys-table').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-action]')
    if (button) void handleKeyAction(button.dataset.action, button.dataset.keyId)
  })

  $('#sign-key').addEventListener('change', () => {
    state.lastSignature = null
    $('#sign-signature').value = ''
    $('#sign-status').className = 'badge neutral'
    $('#sign-status').textContent = 'Waiting'
    $('#sign-meta').innerHTML = '<span class="muted">Sign a payload to see the algorithm, key and signature.</span>'
    $('#verify-result').innerHTML = ''
    updateSignAlgorithms()
  })
  $('#do-sign').addEventListener('click', () => void handleSign())
  $('#do-verify').addEventListener('click', () => void verifyCurrentSignature(false))

  $('#do-random').addEventListener('click', () => void generateRandomBytes())
  $('#do-encrypt').addEventListener('click', () => void encryptData())
  $('#do-decrypt').addEventListener('click', () => void decryptData())

  $('#do-create-did').addEventListener('click', () => void createDid())
  $('#load-dids').addEventListener('click', () => void loadDids())

  $('#run-x509').addEventListener('click', () => void runX509Demo())

  $('#clear-activity').addEventListener('click', () => {
    state.activity = []
    renderActivity()
  })

  $('#json-close').addEventListener('click', () => $('#json-dialog').close())
  $('#json-copy').addEventListener('click', () => void copyText($('#json-dialog-body').textContent))

  document.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-copy]')
    if (!button) return
    const target = document.getElementById(button.dataset.copy)
    if (target) void copyText(target.textContent)
  })
}

wire()
renderKeys()
renderActivity()
void loadInfo()
