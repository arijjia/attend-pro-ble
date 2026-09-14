namespace $ {

	// GATT profile of the AttendPro hub (peripheral) — §4.4, §5.
	// Hub advertises the service; students (centrals) do:
	//   read challenge → write mark → notify receipt → disconnect.

	export const $attendpro_protocol_ble_service = 'c17a0001-38d4-4c6e-9f2a-5b3c7d8e9f01'
	export const $attendpro_protocol_ble_char_challenge = 'c17a0002-38d4-4c6e-9f2a-5b3c7d8e9f01'
	export const $attendpro_protocol_ble_char_mark = 'c17a0003-38d4-4c6e-9f2a-5b3c7d8e9f01'
	export const $attendpro_protocol_ble_char_receipt = 'c17a0004-38d4-4c6e-9f2a-5b3c7d8e9f01'

	// Advertising service data of the AttendPro service:
	//   'AP' (0x41 0x50) | session_handle u32 LE | epoch_index u8 | flags u8 (bit0: closing)
	export const $attendpro_protocol_ble_adv_marker = 0x4150

	// Frames over mark-write and receipt-notify characteristics:
	//   [ seq u8 | total u8 | payload... ]
	// 18 payload bytes + 2 header bytes fit the default ATT MTU of 23.
	export const $attendpro_protocol_ble_chunk_payload = 18

	export function $attendpro_protocol_ble_pack_chunks( bytes: Uint8Array, payload = $attendpro_protocol_ble_chunk_payload ): Uint8Array[] {
		if( ! Number.isInteger( payload ) || payload < 1 || payload > 510 ) throw new Error( 'INVALID_CHUNK_SIZE' )
		const total = Math.max( 1, Math.ceil( bytes.byteLength / payload ) )
		if( total > 255 ) throw new Error( `payload too large: ${ bytes.byteLength } bytes` )
		const frames: Uint8Array[] = []
		for( let seq = 0; seq < total; ++ seq ) {
			const part = bytes.slice( seq * payload, ( seq + 1 ) * payload )
			const frame = new Uint8Array( 2 + part.byteLength )
			frame[0] = seq
			frame[1] = total
			frame.set( part, 2 )
			frames.push( frame )
		}
		return frames
	}

	export type $attendpro_protocol_ble_assembler = {
		fed : ( frame: Uint8Array ) => Uint8Array | null // returns full message when complete
	}

	export function $attendpro_protocol_ble_chunk_assembler(): $attendpro_protocol_ble_assembler {
		let parts: Uint8Array[] = []
		let total = 0
		return {
			fed( frame: Uint8Array ) {
				const seq = frame[0]!, count = frame[1]!
				if( frame.length < 2 || ! count || seq >= count ) {
					parts = []; total = 0
					throw new Error( 'INVALID_FRAME' )
				}
				if( seq === 0 ) { parts = []; total = count }
				if( count !== total || seq !== parts.length ) {
					parts = []; total = 0
					throw new Error( 'OUT_OF_ORDER_FRAME' )
				}
				parts.push( frame.slice( 2 ) )
				if( parts.length !== total ) return null
				const bytes = $attendpro_protocol_concat( ... parts )
				parts = []; total = 0
				return bytes
			},
		}
	}

}
