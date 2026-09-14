namespace $ {

	// In-page demo hub: the very same $attendpro_hub_core witness logic without
	// any radio. Lets colleagues feel the full UX (including receipts) when no
	// BLE hardware is around, and gives the UI something to test against.

	export class $attendpro_transport_demo_hub extends $mol_object {

		core: $attendpro_hub_core | null = null

		static shared: $attendpro_transport_demo_hub | null = null

		static instance(): $attendpro_transport_demo_hub {
			if( ! this.shared ) this.shared = new $attendpro_transport_demo_hub()
			return this.shared
		}

		async persist() {
			if( typeof window === 'undefined' || !this.core ) return
			const core = this.core
			const private_key = async (key: CryptoKey) => $attendpro_protocol_b64u_encode(new Uint8Array(await crypto.subtle.exportKey('pkcs8', key)))
			window.localStorage.setItem('attendpro.demo-hub', JSON.stringify({
				university: await private_key(core.identity.university_private), hub: await private_key(core.identity.hub_private),
				teacher_cred: core.identity.teacher_cred, device_creds: [...core.device_creds],
				session_name: core.session_name, session_id: core.session_id, anchors: core.anchors, accepted: core.accepted,
			}))
		}

		async ensure_session( session_name = 'Демо-пара (без радио)' ) {
			if( this.core && ! this.core.closed ) return this.core
			const stored = typeof window !== 'undefined' ? window.localStorage.getItem('attendpro.demo-hub') : null
			if( stored ) {
				const data = JSON.parse(stored)
				const university = await $attendpro_protocol_key_from_private(data.university)
				const hub = await $attendpro_protocol_key_from_private(data.hub)
				const core = new $attendpro_hub_core({ university_private: university.private_key, university_public: university.public_key, university_public_raw: university.public_raw,
					hub_private: hub.private_key, hub_public: hub.public_key, hub_public_raw: hub.public_raw, hub_key_id: await $attendpro_protocol_key_id(hub.public_raw), teacher_cred: data.teacher_cred })
				core.device_creds = new Map(data.device_creds)
				core.session_name = data.session_name; core.session_id = data.session_id; core.anchors = data.anchors; core.accepted = data.accepted
				this.core = core
				return core
			}
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'Демо-преподаватель' )
			const core = await core_factory()
			await core.session_start( session_name )
			this.core = core
			await this.persist()
			return core
		}

		// demo onboarding: invite with fixed code, always reusable for the fresh key
		async onboard_demo( device_pubkey: string ) {
			const core = await this.ensure_session()
			core.invite_reset( 'DEMO01', 'Демо-студент' )
			const result = await core.onboard( 'DEMO01', device_pubkey )
			await this.persist()
			return result
		}

	}

	export function $attendpro_transport_demo_make( opts: { scan_ms?: number, deliver_ms?: number } = {} ): $attendpro_transport_central {

		const scan_ms = opts.scan_ms ?? 700
		const deliver_ms = opts.deliver_ms ?? 400
		const hub = $attendpro_transport_demo_hub.instance()
		let pending_mark: Uint8Array | null = null
		let receipt_cb: ( ( bytes: Uint8Array ) => void ) | null = null

		async function deliver( bytes: Uint8Array ) {
			const core = await hub.ensure_session()
			const mark = $attendpro_protocol_decode( bytes )
			const result = await core.accept_mark( mark )
			await hub.persist()
			await new Promise( done => setTimeout( done, deliver_ms ) ) // pretend radio round-trip
			if( result.accepted ) {
				receipt_cb?.( $attendpro_protocol_encode( result.accepted.receipt ) )
			}
			// a rejected mark gets no receipt — exactly like real radio
		}

		return {
			label: 'Демо (без радио)',
			async scan( on_found ) {
				await new Promise( done => setTimeout( done, scan_ms ) ) // pretend to listen to the air
				await hub.ensure_session()
				on_found({ device_id: 'demo', name: 'AttendPro · демо' })
			},
			async connect() {},
			async read_challenge() {
				const core = await hub.ensure_session()
				return $attendpro_protocol_encode( core.anchor_current().envelope )
			},
			async write_mark( bytes ) {
				if( receipt_cb ) {
					await deliver( bytes )
				} else {
					pending_mark = bytes
				}
			},
			async subscribe_receipt( on_receipt ) {
				receipt_cb = on_receipt
				const bytes = pending_mark
				if( ! bytes ) return
				pending_mark = null
				await deliver( bytes )
			},
			async disconnect() { receipt_cb = null; pending_mark = null },
		}

	}

}
