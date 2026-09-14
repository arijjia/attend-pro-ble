const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')
const { EventEmitter } = require('node:events')
const $ = require('../scripts/core.cjs')
const { HubStore } = require('./store.cjs')
const { makeGatt } = require('./gatt.cjs')
const { start } = require('./server.cjs')
const p = name => $['$attendpro_protocol_' + name]
async function setup(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(),'attendpro-test-'))
  t.after(() => fs.rm(directory,{recursive:true,force:true}))
  const store = await new HubStore(directory).load()
  await store.start('Тест BLE')
  const key = await p('key_generate')()
  const invite = store.core.invite_create('Студент')
  const bundle = await store.run(c => c.onboard(invite.code,key.public_raw))
  const mark = await p('seal')('mark', { anchor_hash:store.core.anchor_current().hash,credential_hash:bundle.credential_hash,mark_nonce:'0123456789abcdef0123456789abcdef'},key.private_key)
  return {store,key,bundle,mark,directory}
}
test('receipt persists before delivery; exact retries survive restart and epoch rotation', async t => {
  const {store,mark,directory} = await setup(t)
  const result = await store.accept(p('encode')(mark.envelope))
  const restarted = await new HubStore(directory).load()
  await restarted.run(c=>c.epoch_rotate())
  const retry = await restarted.accept(p('encode')(mark.envelope))
  assert.deepEqual(retry.accepted.receipt,result.accepted.receipt)
  assert.equal(restarted.core.accepted.length,1)
})
test('concurrent duplicate submissions issue one receipt', async t => {
  const {store,mark} = await setup(t)
  const results = await Promise.all(Array.from({length:8},()=>store.core.accept_mark(mark.envelope)))
  assert.equal(store.core.accepted.length,1)
  assert.equal(new Set(results.map(r=>r.accepted.receive_seq)).size,1)
})
test('closing races with admission without accepting marks after final batch',async t=>{
  const {store,mark}=await setup(t)
  const [accepted,final] = await Promise.all([store.core.accept_mark(mark.envelope),store.core.session_close()])
  assert.ok(accepted.accepted)
  assert.equal(final.batch.envelope.body.count,1)
  assert.equal((await store.core.accept_mark(mark.envelope)).rejected.reason,'SESSION_CLOSED')
})
test('concurrent use of an invite issues only one credential',async t=>{
  const {store,key}=await setup(t)
  const invite=store.core.invite_create('Один')
  const results=await Promise.allSettled([store.core.onboard(invite.code,key.public_raw),store.core.onboard(invite.code,key.public_raw)])
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1)
})
test('GATT at MTU 23 transfers long challenge, signed mark and fragmented receipt',async t=>{
  const {store,mark,bundle}=await setup(t)
  class Characteristic { static RESULT_SUCCESS=0; static RESULT_INVALID_OFFSET=7; static RESULT_UNLIKELY_ERROR=14; constructor(options){Object.assign(this,options)} }
  const bleno=Object.assign(new EventEmitter(),{Characteristic,PrimaryService:class{constructor(options){Object.assign(this,options)}}})
  const {service}=makeGatt(bleno,store)
  const [challenge,write,notify]=service.characteristics
  const assembler=p('ble_chunk_assembler')()
  let anchor
  while(!anchor){challenge.onReadRequest(0,(status,data)=>{assert.equal(status,0);assert.ok(data.length<=20);anchor=assembler.fed(data)})}
  assert.equal(p('decode')(anchor).body.session_id,store.core.session_id)
  const received=p('ble_chunk_assembler')()
  const receiptPromise=new Promise(resolve=>notify.onSubscribe(20,data=>{
    assert.ok(data.length<=20)
    const full=received.fed(data)
    queueMicrotask(()=>notify.onNotify())
    if(full)resolve(p('decode')(full))
    return true
  }))
  for(const frame of p('ble_pack_chunks')(p('encode')(mark.envelope))) await new Promise(resolve=>write.onWriteRequest(frame,0,false,status=>{assert.equal(status,0);resolve()}))
  const receipt=await receiptPromise
  const verdict=await p('verify_evidence')({mark:mark.envelope,receipt,anchor:p('decode')(anchor),device_cred:bundle.credential},store.core.identity.university_public,store.core.identity.hub_public,Math.floor(Date.now()/1000))
  assert.equal(verdict.ok,true)
  bleno.emit('disconnect')
})
test('framing rejects malformed/out-of-order packets and supports successive messages',()=>{
  const a=p('ble_chunk_assembler')()
  assert.throws(()=>a.fed(Uint8Array.of(0,0)))
  assert.throws(()=>a.fed(Uint8Array.of(2,3,9)))
  for(const value of [1,2]) assert.deepEqual(a.fed(Uint8Array.of(0,1,value)),Uint8Array.of(value))
  assert.throws(()=>p('ble_pack_chunks')(Uint8Array.of(1),0))
})
test('HTTP console authorization, onboarding, persistence and exports',async t=>{
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'attendpro-http-'))
  const app=await start({directory,noBle:true,port:0,origins:'https://localhost'})
  t.after(async()=>{await app.close();await fs.rm(directory,{recursive:true,force:true})})
  const base='http://127.0.0.1:'+app.server.address().port
  const headers={authorization:'Bearer '+app.token,'content-type':'application/json'}
  assert.equal((await fetch(base+'/api/status')).status,401)
  assert.equal((await fetch(base+'/api/start',{method:'POST',headers:{...headers,origin:'https://attacker.test'},body:'{}'})).status,403)
  const post=async(route,body,admin=true)=>{const r=await fetch(base+'/api/'+route,{method:'POST',headers:admin?headers:{'content-type':'application/json'},body:JSON.stringify(body)});return [r.status,await r.json()]}
  assert.equal((await post('start',{session_name:'HTTP'}))[0],200)
  const [,invite]=await post('invite',{student_name:'Мария'})
  const key=await p('key_generate')()
  assert.equal((await post('onboard',{code:invite.code,pubkey:key.public_raw},false))[0],200)
  assert.equal((await post('onboard',{code:invite.code,pubkey:key.public_raw},false))[0],400)
  assert.equal((await post('close',{}))[0],200)
  const exported=await (await fetch(base+'/api/export',{headers})).json()
  assert.ok(exported.final.batch)
  assert.ok(!JSON.stringify(exported).includes('private'))
})
