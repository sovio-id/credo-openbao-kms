// Copies the version that `changeset version` wrote to package.json into
// jsr.json, so the npm and JSR packages always release the same version. Only
// the version line is replaced, which keeps the hand-formatted rest of jsr.json.
import { readFileSync, writeFileSync } from 'node:fs'

const { version } = JSON.parse(readFileSync('package.json', 'utf8'))
const source = readFileSync('jsr.json', 'utf8')
const updated = source.replace(/("version":\s*")[^"]*(")/, `$1${version}$2`)

if (updated === source) {
  console.log(`jsr.json already at ${version}`)
} else {
  writeFileSync('jsr.json', updated)
  console.log(`jsr.json set to ${version}`)
}
