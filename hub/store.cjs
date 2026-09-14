const fs = require('node:fs')
const path = require('node:path')
const $ = require('../scripts/core.cjs')
const p = name => $['$attendpro_protocol_' + name]

class HubStore {
  constructor(directory) { this.directory = directory; this.tail = Promise.resolve(); this.final = null }
  async load() {
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 })
    const file = path.join(this.directory, 'state.json')
    if (fs.existsSync(file)) {
      const state = JSON.parse(fs.readFileSync(file, 'utf8'))
      const university = await p('key_from_private')(state.university_private)
      const hub = await p('key_from_private')(state.hub_private)
      this.core = new $.$attendpro_hub_core({ university_private: university.private_key, university_public: university.public_key,
        university_public_raw: university.public_raw, hub_private: hub.private_key, hub_public: hub.public_key,
        hub_public_raw: hub.public_raw, hub_key_id: await p('key_id')(hub.public_raw), teacher_cred: state.teacher_cred })
      Object.assign(this.core, state.session)
      this.core.device_creds = new Map(state.device_creds)
      this.core.invites = state.invites
      this.final = state.final
    } else {
      this.core = await (await $.$attendpro_hub_core.bootstrap('cit', 'Преподаватель MVP')).core_factory()
      await this.save()
    }
    return this
  }
  async save() {
    const c = this.core
    const privateKey = async key => p('b64u_encode')(new Uint8Array(await crypto.subtle.exportKey('pkcs8', key)))
    const state = { university_private: await privateKey(c.identity.university_private), hub_private: await privateKey(c.identity.hub_private),
      teacher_cred: c.identity.teacher_cred, device_creds: [...c.device_creds], invites: c.invites, final: this.final,
      session: Object.fromEntries(['session_name','session_id','policy_hash','anchors','accepted','closed'].map(k => [k,c[k]])) }
    const file = path.join(this.directory, 'state.json'), temp = file + '.tmp'
    const fd = fs.openSync(temp, 'w', 0o600)
    try { fs.writeFileSync(fd, JSON.stringify(state)); fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
    fs.renameSync(temp, file)
  }
  run(action) {
    const task = this.tail.then(async () => {
      if (this.failed) throw new Error('STORAGE_FAILED_RESTART_REQUIRED')
      const result = await action(this.core)
      try { await this.save() } catch (error) { this.failed = true; throw error }
      return result
    })
    this.tail = task.catch(() => {})
    return task
  }
  start(name) {
    return this.run(async core => {
      if (core.anchors.length && !core.closed) throw new Error('SESSION_ALREADY_STARTED')
      if (core.anchors.length) {
        fs.writeFileSync(path.join(this.directory, core.session_id + '.json'), JSON.stringify(this.export()), { mode: 0o600 })
        const next = new $.$attendpro_hub_core(core.identity)
        next.device_creds = core.device_creds; next.invites = core.invites
        this.core = next
      }
      this.final = null
      return this.core.session_start(name)
    })
  }
  accept(bytes) { return this.run(core => core.accept_mark(p('decode')(bytes))) }
  export() {
    return { anchors: this.core.anchors, accepted: this.core.accepted, device_creds: [...this.core.device_creds],
      teacher_cred: this.core.identity.teacher_cred, university_public_raw: this.core.identity.university_public_raw, final: this.final }
  }
}
module.exports = { HubStore }
