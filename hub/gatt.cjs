const $ = require('../scripts/core.cjs')
const p = name => $['$attendpro_protocol_' + name]
// bleno supports a single central. Reset all per-connection buffers on disconnect.
function makeGatt(bleno, store) {
  const C = bleno.Characteristic
  let challenge = [], assembler = p('ble_chunk_assembler')(), notify = null, generation = 0
  let sending = false, outgoing = []
  const reset = () => { challenge = []; assembler = p('ble_chunk_assembler')(); notify = null; outgoing = []; sending = false; generation++ }
  const pump = () => {
    if (!notify || sending || !outgoing.length) return
    sending = true
    const frame = outgoing.shift()
    if (notify(Buffer.from(frame)) === false) { outgoing.unshift(frame); sending = false; setTimeout(pump, 30) }
  }
  const receipt = new C({ uuid: p('ble_char_receipt'), properties: ['notify'],
    onSubscribe(_size, callback) { notify = callback },
    onUnsubscribe() { reset() },
    onNotify() { sending = false; pump() },
  })
  const anchor = new C({ uuid: p('ble_char_challenge'), properties: ['read'],
    onReadRequest(offset, callback) {
      try {
        if (offset) return callback(C.RESULT_INVALID_OFFSET)
        if (!challenge.length) challenge = p('ble_pack_chunks')(p('encode')(store.core.anchor_current().envelope))
        callback(C.RESULT_SUCCESS, Buffer.from(challenge.shift()))
      } catch { callback(C.RESULT_UNLIKELY_ERROR) }
    },
  })
  const mark = new C({ uuid: p('ble_char_mark'), properties: ['write'],
    onWriteRequest(data, offset, _withoutResponse, callback) {
      if (offset) return callback(C.RESULT_INVALID_OFFSET)
      const connection = generation
      let bytes
      try { bytes = assembler.fed(new Uint8Array(data)) } catch { return callback(C.RESULT_UNLIKELY_ERROR) }
      if (!bytes) return callback(C.RESULT_SUCCESS)
      store.accept(bytes).then(result => {
        if (!result.accepted) return callback(C.RESULT_UNLIKELY_ERROR)
        callback(C.RESULT_SUCCESS)
        if (connection !== generation) return
        outgoing.push(...p('ble_pack_chunks')(p('encode')(result.accepted.receipt)))
        pump()
      }).catch(() => callback(C.RESULT_UNLIKELY_ERROR))
    },
  })
  bleno.on('disconnect', reset)
  return { service: new bleno.PrimaryService({ uuid: p('ble_service'), characteristics: [anchor, mark, receipt] }), reset }
}
module.exports = { makeGatt }
