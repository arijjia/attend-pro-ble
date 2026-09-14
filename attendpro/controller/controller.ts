namespace $ {

	// One-tap mark flow controller (§8.4). Owns the UX state machine:
	// idle → scanning → connecting → verifying → marking → waiting_receipt → done/failed.
	// The green checkmark appears only after a cryptographically verified Receipt.

	export type $attendpro_controller_phase =
		| 'idle'
		| 'no_identity'
		| 'no_radio'
		| 'scanning'
		| 'not_found'
		| 'connecting'
		| 'verifying'
		| 'marking'
		| 'waiting_receipt'
		| 'receipt_timeout'
		| 'accepted'
		| 'failed'
		| 'already_marked'

	export class $attendpro_controller extends $mol_object {

		identity: $attendpro_identity = null!
		private attempt = 0

		// test seams: fixed transport + shortened timings
		transport_override: $attendpro_transport_central | null = null
		receipt_wait_ms = 15000
		scan_ms = 5000

		@ $mol_mem
		phase( next?: $attendpro_controller_phase ): $attendpro_controller_phase {
			return next ?? 'idle'
		}

		@ $mol_mem
		message( next?: string ): string {
			return next ?? ''
		}

		@ $mol_mem
		found_name( next?: string ): string {
			return next ?? ''
		}

		@ $mol_mem
		last_receipt_hash( next?: string ): string {
			return next ?? ''
		}

		@ $mol_mem
		demo_mode( next?: boolean ): boolean {
			return next ?? this.identity?.bundle()?.demo ?? false
		}

		busy() {
			return [ 'scanning', 'connecting', 'verifying', 'marking', 'waiting_receipt' ].includes( this.phase() )
		}

		transport(): $attendpro_transport_central | null {
			if( this.transport_override ) return this.transport_override
			if( this.demo_mode() ) return $attendpro_transport_demo_make()
			const available = $attendpro_transport_available()
			if( available.capacitor ) return $attendpro_transport_capacitor_make()
			if( available.web ) return $attendpro_transport_web_make()
			return null
		}

		transport_label(): string {
			if( this.demo_mode() ) return 'демо'
			const available = $attendpro_transport_available()
			if( available.capacitor ) return 'Capacitor BLE'
			if( available.web ) return 'Web Bluetooth'
			return 'нет радио'
		}

		// ── the flow ──────────────────────────────────────────────────────

		async mark( evidence: $attendpro_evidence ): Promise<void> {

			if( this.busy() ) return
			const bundle = this.identity.bundle()
			if( ! bundle ) {
				this.phase( 'no_identity' )
				this.message( 'Сначала получите ключ устройства — код приглашения выдаёт преподаватель' )
				return
			}

			const transport = this.transport()
			if( ! transport ) {
				this.phase( 'no_radio' )
				this.message( 'BLE недоступен: установите нативное приложение или откройте в Chrome, либо включите демо-режим' )
				return
			}

			const attempt = ++this.attempt
			try {

				// 1. scan the air for the hub advertisement
				this.phase( 'scanning' )
				this.message( 'Слушаю эфир…' )
				this.found_name( '' )
				const found_box: $attendpro_transport_found[] = []
				await transport.scan( f => found_box.push( f ), this.scan_ms )
				const found = found_box[0] ?? null
				if( ! found ) {
					this.phase( 'not_found' )
					this.message( 'Пара не найдена. Подойдите ближе к хабу преподавателя и попробуйте снова' )
					return
				}
				this.found_name( found.name )
				this.message( `Найдено: ${ found.name }` )

				// 2. connect (short session with jitter, §5 rule 2)
				this.phase( 'connecting' )
				this.message( 'Подключаюсь…' )
				await transport.connect( found.device_id )

				// 3. read the anchor and verify it BEFORE creating any Mark (§8.4 step 4)
				this.phase( 'verifying' )
				this.message( 'Проверяю подпись якоря…' )
				const anchor_bytes = await transport.read_challenge()
				const anchor = $attendpro_protocol_decode( anchor_bytes )
				const anchor_body = anchor.body as unknown as $attendpro_protocol_anchor_body

				const teacher_body = bundle.teacher_cred.body as unknown as $attendpro_protocol_teacher_cred_body
				const university_public = await $attendpro_protocol_key_import_public( bundle.university_public_raw )
				const teacher_check = await $attendpro_protocol_open( bundle.teacher_cred, university_public )
				if( bundle.teacher_cred.kind !== 'teacher_cred' || teacher_body.role !== 'teacher' || ! teacher_check.ok ) throw new Error( 'TEACHER_CRED_BAD_SIGNATURE' )
				const hub_public = await $attendpro_protocol_key_import_public( teacher_body.hub_pubkey )
				const hub_key_id = await $attendpro_protocol_key_id( teacher_body.hub_pubkey )
				const anchor_check = await $attendpro_protocol_check_anchor_trusted( anchor, hub_public, hub_key_id )
				if( ! anchor_check.ok ) throw new Error( `ANCHOR_${ anchor_check.reason }` )

				// already marked this session?
				if( evidence.records().some( r => r.session_id === anchor_body.session_id && r.receipt && (r.mark.body as unknown as $attendpro_protocol_mark_body).credential_hash === bundle.credential_hash ) ) {
					this.phase( 'already_marked' )
					this.message( `Вы уже отмечены на «${ anchor_body.session_name }»` )
					await transport.disconnect()
					return
				}

				// 4. create and sign the Mark — no time field by design (§4.2 F2)
				this.phase( 'marking' )
				this.message( 'Подписываю отметку…' )
				const keys = await this.identity.keys_of( bundle )
				const anchor_hash = await $attendpro_protocol_hash_of_envelope( anchor )
				const pending = evidence.records().find( r => r.session_id === anchor_body.session_id && !r.receipt && (r.mark.body as unknown as $attendpro_protocol_mark_body).credential_hash === bundle.credential_hash )
				const sealed = pending ? { envelope: pending.mark, hash: pending.mark_hash } : await $attendpro_protocol_seal( 'mark', {
					anchor_hash,
					credential_hash: bundle.credential_hash,
					mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
				}, keys.private_key )


				if( !pending ) evidence.append({
					session_id: anchor_body.session_id,
					session_name: anchor_body.session_name,
					mark: sealed.envelope,
					mark_hash: sealed.hash,
					anchor,
					receipt: null,
					received_at: Math.floor( Date.now() / 1000 ),
				})

				// 5. write it to the hub and wait for the Receipt
				this.phase( 'waiting_receipt' )
				this.message( 'Отправляю отметку…' )
				await transport.subscribe_receipt( bytes => { if( attempt === this.attempt ) void this.receipt_incoming( bytes, sealed.hash, evidence, attempt ) } )
				await transport.write_mark( $attendpro_protocol_encode( sealed.envelope ) )



				// receipt arrives through subscription; give the radio some time
				const started = Date.now()
				while( Date.now() - started < this.receipt_wait_ms ) {
					if( this.phase() === 'accepted' ) break
					await new Promise( done => setTimeout( done, 50 ) )
				}
				if( this.phase() !== 'accepted' ) {
					this.phase( 'receipt_timeout' )
					this.message( 'Отметка сохранена локально, но квитанция от хаба не пришла — попробуйте ещё раз' )
				}
				await transport.disconnect()

			} catch( error ) {
				this.phase( 'failed' )
				this.message( `Ошибка: ${ (error as Error).message }` )
			} finally {
				++this.attempt
				try { await transport.disconnect() } catch {}
			}
		}

		// receipt path: verify hub signature first, only then show the green checkmark
		async receipt_incoming( bytes: Uint8Array, mark_hash: string, evidence: $attendpro_evidence, attempt?: number ) {
			try {
				const receipt = $attendpro_protocol_decode( bytes )
				const bundle = this.identity.bundle()
				if( ! bundle ) throw new Error( 'NO_IDENTITY' )
				const teacher_body = bundle.teacher_cred.body as unknown as $attendpro_protocol_teacher_cred_body
				const hub_public = await $attendpro_protocol_key_import_public( teacher_body.hub_pubkey )
				const opened = await $attendpro_protocol_open( receipt, hub_public )
				if( ! opened.ok ) throw new Error( `RECEIPT_${ opened.reason }` )
				if( receipt.kind !== 'receipt' ) throw new Error( 'NOT_RECEIPT' )
				const record = evidence.records().find( r => r.mark_hash === mark_hash )
				if( !record ) throw new Error( 'UNKNOWN_MARK' )
				const receipt_body = receipt.body as unknown as $attendpro_protocol_receipt_body
				if( receipt_body.anchor_hash !== (record.mark.body as unknown as $attendpro_protocol_mark_body).anchor_hash || receipt_body.epoch_state !== 'open' || !Number.isSafeInteger(receipt_body.receive_seq) || receipt_body.receive_seq < 1 ) throw new Error( 'RECEIPT_BAD_BINDING' )
				if( receipt_body.mark_hash !== mark_hash ) throw new Error( 'RECEIPT_FOREIGN_MARK' )

				if( attempt !== undefined && attempt !== this.attempt ) return
				evidence.attach_receipt( mark_hash, receipt )
				this.last_receipt_hash( opened.hash! )
				this.phase( 'accepted' )
				this.message( `✓ Принято преподавателем (квитанция №${ receipt_body.receive_seq })` )
			} catch( error ) {
				if( attempt !== undefined && attempt !== this.attempt ) return
				this.message( `Квитанция отклонена: ${ (error as Error).message }` )
			}
		}

	}

}
