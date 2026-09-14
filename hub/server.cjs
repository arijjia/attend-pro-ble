const http = require('node:http')
const https = require('node:https')
const fs = require('node:fs')
const path = require('node:path')
const { randomBytes, timingSafeEqual } = require('node:crypto')
const { HubStore } = require('./store.cjs')
const { makeGatt } = require('./gatt.cjs')
const $ = require('../scripts/core.cjs')

async function start(options = {}) {
  const store = await new HubStore(options.directory || path.join(__dirname, 'data')).load()
  const tokenFile = path.join(store.directory, 'admin-token')
  if (!fs.existsSync(tokenFile)) fs.writeFileSync(tokenFile, randomBytes(24).toString('hex'), { mode: 0o600 })
  const token = fs.readFileSync(tokenFile, 'utf8').trim()
  let radio = options.noBle ? 'disabled' : 'starting', bleno
  if (!options.noBle) {
    bleno = require('@abandonware/bleno')
    const { service } = makeGatt(bleno, store)
    const advertise = state => {
      radio = state
      if (state !== 'poweredOn') return bleno.stopAdvertising()
      bleno.startAdvertising('AttendPro', [$.$attendpro_protocol_ble_service], error => {
        if (error) { radio = error.message; return }
        bleno.setServices([service], error => { radio = error ? error.message : 'advertising' })
      })
    }
    bleno.on('stateChange', advertise)
    bleno.on('error', error => { radio = error.message })
    if (bleno.state === 'poweredOn') advertise(bleno.state)
  }
  const origins = new Set((options.origins || '').split(',').filter(Boolean))
  const handler = async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)) }
    const url = new URL(req.url, 'http://localhost')
    const origin = req.headers.origin
    const ownOrigin = `${options.tls ? 'https' : 'http'}://${req.headers.host}`
    if (origin && origin !== ownOrigin) {
      if (!origins.has(origin)) return send(403, { error: 'ORIGIN_NOT_ALLOWED' })
      res.setHeader('access-control-allow-origin', origin)
      res.setHeader('vary', 'Origin')
      res.setHeader('access-control-allow-headers', 'content-type, authorization')
      res.setHeader('access-control-allow-methods', 'GET, POST, OPTIONS')
    }
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return }
    try {
      if (url.pathname.startsWith('/api/')) {
        if (url.pathname !== '/api/onboard') {
          const provided = Buffer.from((req.headers.authorization || '').replace(/^Bearer /, ''))
          const expected = Buffer.from(token)
          if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return send(401, { error: 'ADMIN_TOKEN_REQUIRED' })
        }
        let body = {}
        if (req.method === 'POST') {
          let text = ''
          for await (const chunk of req) { text += chunk; if (Buffer.byteLength(text) > 8192) return send(413, { error: 'BODY_TOO_LARGE' }) }
          body = JSON.parse(text || '{}')
        }
        const textField = (field, max = 100) => { const value = body[field]; if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error('INVALID_' + field); return value.trim() }
        if (req.method === 'GET' && url.pathname === '/api/status') return send(200, { radio, session_id: store.core.session_id, session_name: store.core.session_name, closed: store.core.closed, epoch: store.core.anchors.length - 1, accepted: store.core.accepted.map(({student_name, receive_seq}) => ({student_name, receive_seq})) })
        if (req.method === 'GET' && url.pathname === '/api/export') return send(200, store.export())
        if (req.method === 'POST') {
          if (url.pathname === '/api/onboard') { const code = textField('code', 12), key = textField('pubkey', 128); return send(200, await store.run(c => c.onboard(code, key))) }
          if (url.pathname === '/api/invite') { const name = textField('student_name'); return send(200, await store.run(c => c.invite_create(name))) }
          if (url.pathname === '/api/start') return send(200, await store.start(textField('session_name', 80)))
          if (url.pathname === '/api/rotate') return send(200, await store.run(c => c.epoch_rotate()))
          if (url.pathname === '/api/close') return send(200, await store.run(async c => (store.final = await c.session_close())))
        }
        return send(404, { error: 'NOT_FOUND' })
      }
      if (req.method !== 'GET') return send(405, { error: 'METHOD_NOT_ALLOWED' })
      const filename = url.pathname === '/' ? path.join(__dirname, 'console.html') : path.join(__dirname, '../dist', decodeURIComponent(url.pathname))
      const root = path.resolve(__dirname, '../dist') + path.sep
      if (url.pathname !== '/' && !path.resolve(filename).startsWith(root)) return send(404, {error:'NOT_FOUND'})
      if (!fs.existsSync(filename) || !fs.statSync(filename).isFile()) return send(404, { error: 'NOT_FOUND' })
      const mime = { '.html':'text/html; charset=utf-8', '.js':'text/javascript', '.css':'text/css', '.json':'application/json', '.webmanifest':'application/manifest+json', '.png':'image/png', '.svg':'image/svg+xml' }
      res.writeHead(200, { 'content-type': mime[path.extname(filename)] || 'application/octet-stream', 'cache-control': 'no-cache' })
      fs.createReadStream(filename).pipe(res)
    } catch (error) { send(400, { error: error.message }) }
  }
  const server = options.tls ? https.createServer(options.tls, handler) : http.createServer(handler)
  await new Promise(resolve => server.listen(options.port ?? 8877, options.host || '127.0.0.1', resolve))
  const timer = setInterval(() => {
    if (store.core.anchors.length && !store.core.closed) store.run(c => c.epoch_rotate()).catch(error => console.error('Epoch:', error.message))
  }, options.epochMs || 300000)
  const close = async () => { clearInterval(timer); bleno?.stopAdvertising(); await store.tail; await new Promise(resolve => server.close(resolve)) }
  return { server, store, token, close }
}
module.exports = { start }
if (require.main === module) {
  const tls = process.env.TLS_CERT && process.env.TLS_KEY ? { cert: fs.readFileSync(process.env.TLS_CERT), key: fs.readFileSync(process.env.TLS_KEY) } : null
  start({ noBle: process.argv.includes('--no-ble'), host: process.env.HOST, port: Number(process.env.PORT || 8877), origins: process.env.ALLOWED_ORIGINS, tls }).then(app => {
    console.log(`AttendPro: ${tls ? 'https' : 'http'}://${process.env.HOST || '127.0.0.1'}:${app.server.address().port}/`)
    console.log('Ключ консоли: hub/data/admin-token (введите его в поле консоли)')
    for (const signal of ['SIGINT','SIGTERM']) process.on(signal, () => { app.close().then(() => process.exit(0)) })
  }).catch(error => { console.error(error); process.exitCode = 1 })
}
