const ts = require('typescript')
const fs = require('node:fs')
const path = require('node:path')
const files = ['protocol/protocol.ts', 'protocol/facts.ts', 'protocol/ble.ts', 'hub/core/hub_core.ts']
const source = files.map(file => fs.readFileSync(path.join(__dirname, '../attendpro', file), 'utf8')).join('\n')
const output = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText
module.exports = new Function(output + '\nreturn $;')()
