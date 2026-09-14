namespace $ {

	// BLE central role of the student app (§5): scan → connect → read anchor →
	// write mark → receive receipt → disconnect. Three interchangeable backends:
	//  · Capacitor shell (@capacitor-community/bluetooth-le behind a global shim)
	//  · Web Bluetooth (desktop/Android Chrome)
	//  · in-page demo hub (no radio at all)

	export type $attendpro_transport_found = {
		device_id : string
		name : string
	}

	export type $attendpro_transport_central = {
		label : string
		// resolves after ms; calls on_found for each advertising hub (demo: immediately)
		scan( on_found: ( found: $attendpro_transport_found ) => void, ms: number ): Promise<void>
		connect( device_id: string ): Promise<void>
		read_challenge(): Promise<Uint8Array>
		write_mark( bytes: Uint8Array ): Promise<void>
		subscribe_receipt( on_receipt: ( bytes: Uint8Array ) => void ): Promise<void>
		disconnect(): Promise<void>
	}

	export function $attendpro_transport_available(): { capacitor: boolean, web: boolean } {
		const shim = ( globalThis as { CapBLE?: { BleClient?: unknown } } ).CapBLE
		const cap = !! shim?.BleClient
		const web = typeof navigator !== 'undefined' && !! ( navigator as { bluetooth?: unknown } ).bluetooth
		return { capacitor: cap, web }
	}

	// ── dataView helpers (plugin/web APIs speak DataView) ──────────────────

	function view_bytes( view: DataView ): Uint8Array {
		return new Uint8Array( view.buffer, view.byteOffset, view.byteLength )
	}

	function bytes_view( bytes: Uint8Array ): DataView {
		return new DataView( bytes.buffer, bytes.byteOffset, bytes.byteLength )
	}

	async function read_frames( read: () => Promise<DataView> ): Promise<Uint8Array> {
		const assembler = $attendpro_protocol_ble_chunk_assembler()
		for( let i = 0; i < 255; ++i ) {
			const bytes = assembler.fed( view_bytes( await read() ) )
			if( bytes ) return bytes
		}
		throw new Error( 'CHALLENGE_TOO_LARGE' )
	}

	// ── Capacitor backend ──────────────────────────────────────────────────

	type $attendpro_transport_cap_ble = {
		BleClient : {
			initialize() : Promise<void>
			requestEnable() : Promise<void>
			requestLEScan( options: Record<string, unknown>, cb: ( result: { device: { deviceId: string, name?: string }, manufacturerData?: Record<string, DataView>, serviceData?: Record<string, DataView> } ) => void ) : Promise<void>
			stopLEScan() : Promise<void>
			requestMtu?( deviceId: string, mtu: number ) : Promise<void>
			connect( deviceId: string, onDisconnect?: () => void ) : Promise<void>
			read( deviceId: string, service: string, characteristic: string ) : Promise<DataView>
			write( deviceId: string, service: string, characteristic: string, value: DataView ) : Promise<void>
			startNotifications( deviceId: string, service: string, characteristic: string, cb: ( value: DataView ) => void ) : Promise<void>
			disconnect( deviceId: string ) : Promise<void>
		}
	}

	// The Capacitor shell exposes window.CapBLE = { BleClient } (esbuild IIFE shim),
	// so the MAM web bundle stays free of npm dependencies.
	declare const CapBLE : $attendpro_transport_cap_ble | undefined

	export function $attendpro_transport_capacitor_make(): $attendpro_transport_central {
		const ble = ( globalThis as unknown as { CapBLE?: $attendpro_transport_cap_ble } ).CapBLE!.BleClient
		let device_id = ''
		const service = $attendpro_protocol_ble_service
		const char_challenge = $attendpro_protocol_ble_char_challenge
		const char_mark = $attendpro_protocol_ble_char_mark
		const char_receipt = $attendpro_protocol_ble_char_receipt

		return {
			label: 'Capacitor BLE',
			async scan( on_found, ms ) {
				await ble.initialize()
				await ble.requestEnable().catch( () => {} )
				await ble.requestLEScan(
					{ services: [ service ], allowDuplicates: false },
					result => {
						const name = result.device.name || 'AttendPro'
						on_found({ device_id: result.device.deviceId, name })
					},
				)
				await new Promise( done => setTimeout( done, ms ) )
				await ble.stopLEScan()
			},
			async connect( id ) {
				device_id = id
				await ble.connect( id )
				await ble.requestMtu?.( id, 512 ).catch( () => {} )
			},
			async read_challenge() {
				return read_frames( () => ble.read( device_id, service, char_challenge ) )
			},
			async write_mark( bytes ) {
				for( const frame of $attendpro_protocol_ble_pack_chunks( bytes ) ) {
					await ble.write( device_id, service, char_mark, bytes_view( frame ) )
				}
			},
			async subscribe_receipt( on_receipt ) {
				const assembler = $attendpro_protocol_ble_chunk_assembler()
				await ble.startNotifications( device_id, service, char_receipt, view => {
					const full = assembler.fed( view_bytes( view ) )
					if( full ) on_receipt( full )
				} )
			},
			async disconnect() {
				await ble.disconnect( device_id ).catch( () => {} )
			},
		}
	}

	// ── Web Bluetooth backend (desktop / Android Chrome) ───────────────────

	interface WebBluetoothCharacteristic {
		readValue(): Promise<DataView>
		writeValue( value: BufferSource ): Promise<void>
		startNotifications(): Promise<WebBluetoothCharacteristic>
		addEventListener( type: 'characteristicvaluechanged', listener: ( event: Event ) => void ): void
	}

	interface WebBluetoothService {
		getCharacteristic( uuid: string ): Promise<WebBluetoothCharacteristic>
	}

	interface WebBluetoothServer {
		getPrimaryService( uuid: string ): Promise<WebBluetoothService>
	}

	interface WebBluetoothDevice {
		name?: string
		gatt: {
			connect(): Promise<WebBluetoothServer>
			disconnect(): void
		}
	}

	export function $attendpro_transport_web_make(): $attendpro_transport_central {
		let challenge_char: WebBluetoothCharacteristic | null = null
		let mark_char: WebBluetoothCharacteristic | null = null
		let receipt_char: WebBluetoothCharacteristic | null = null
		let device: WebBluetoothDevice | null = null

		async function chars() {
			const server = await device!.gatt.connect()
			const service = await server.getPrimaryService( $attendpro_protocol_ble_service )
			challenge_char = await service.getCharacteristic( $attendpro_protocol_ble_char_challenge )
			mark_char = await service.getCharacteristic( $attendpro_protocol_ble_char_mark )
			receipt_char = await service.getCharacteristic( $attendpro_protocol_ble_char_receipt )
		}

		return {
			label: 'Web Bluetooth',
			async scan( on_found ) {
				// browsers expose no open scan: the OS picker IS our scan (user gesture required)
				device = await ( navigator as unknown as { bluetooth: { requestDevice( opts: unknown ): Promise<WebBluetoothDevice> } } )
					.bluetooth.requestDevice({ filters: [{ services: [ $attendpro_protocol_ble_service ] }] })
				on_found({ device_id: 'web', name: device.name || 'AttendPro' })
			},
			async connect() {
				await chars()
			},
			async read_challenge() {
				return read_frames( () => challenge_char!.readValue() )
			},
			async write_mark( bytes ) {
				for( const frame of $attendpro_protocol_ble_pack_chunks( bytes ) ) {
					await mark_char!.writeValue( frame as unknown as BufferSource )
				}
			},
			async subscribe_receipt( on_receipt ) {
				const assembler = $attendpro_protocol_ble_chunk_assembler()
								receipt_char!.addEventListener( 'characteristicvaluechanged', ( event: Event ) => {
					const target = event.target as unknown as { value: DataView }
					const full = assembler.fed( view_bytes( target.value ) )
					if( full ) on_receipt( full )
				} )
				await receipt_char!.startNotifications()
			},
			async disconnect() {
				device?.gatt.disconnect()
			},
		}
	}

}
