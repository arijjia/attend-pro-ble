namespace $.$$ {

	export class $attendpro_student extends $.$attendpro_student {

		@ $mol_mem
		identity() {
			return this.$.$attendpro_identity.make({ $: this.$ })
		}

		@ $mol_mem
		evidence() {
			return this.$.$attendpro_evidence.make({ $: this.$ })
		}

		@ $mol_mem
		controller() {
			return this.$.$attendpro_controller.make({ $: this.$, identity: this.identity() })
		}

		// ── status card ──────────────────────────────────────────────────

		override status_line(): string {
			const phase = this.controller().phase()
			switch( phase ) {
				case 'idle': return 'Готов к отметке'
				case 'scanning': return 'Слушаю эфир…'
				case 'not_found': return 'Пара не найдена'
				case 'connecting': return 'Подключаюсь к хабу…'
				case 'verifying': return 'Проверяю подпись якоря…'
				case 'marking': return 'Подписываю отметку…'
				case 'waiting_receipt': return 'Отправлено, жду квитанцию…'
				case 'accepted': return this.controller().message()
				case 'already_marked': return this.controller().message()
				case 'receipt_timeout': return 'Квитанция не получена'
				case 'no_identity': return 'Устройство не настроено'
				case 'no_radio': return 'Радио недоступно'
				default: return this.controller().message() || 'Что-то пошло не так'
			}
		}

		override status_details(): string {
			const phase = this.controller().phase()
			if( this.controller().found_name() && [ 'connecting', 'verifying', 'marking', 'waiting_receipt' ].includes( phase ) ) {
				return `Найдена пара: ${ this.controller().found_name() }`
			}
			if( phase === 'idle' ) return 'Нажмите «Отметиться» рядом с хабом преподавателя'
			if( phase === 'accepted' ) return 'Квитанция хаба проверена и сохранена на устройстве'
			return this.controller().message()
		}

		override status_type(): string {
			switch( this.controller().phase() ) {
				case 'accepted':
				case 'already_marked': return 'success'
				case 'failed':
				case 'no_identity':
				case 'no_radio':
				case 'not_found':
				case 'receipt_timeout': return 'danger'
				default: return ''
			}
		}

		override mark_label(): string {
			return this.controller().busy() ? 'Минуточку…' : 'Отметиться'
		}

		override mark_enabled(): boolean {
			return ! this.controller().busy()
		}

		override mark( next?: Event ): null {
			if( next === undefined ) return null
			this.$.$mol_wire_async( this.controller() ).mark( this.evidence() )
			return null
		}

		// ── body composition (conditional cards) ─────────────────────────

		override body() {
			const rows: any[] = [ this.Status() ]
			if( ! this.identity().bundle() ) {
				rows.push( this.Setup() )
			} else if( this.evidence().records().length ) {
				rows.push( this.History_title(), this.History() )
			} else {
				rows.push( this.Empty_hint() )
			}
			rows.push( this.Reset_button() )
			return rows as any
		}

		// ── onboarding card ─────────────────────────────────────────────

		override setup_enabled(): boolean {
			return this.hub_url().length > 0 && this.invite_code().length >= 4
		}

		override setup( next?: Event ): null {
			if( next === undefined ) return null
			this.$.$mol_wire_async( this ).setup_async()
			return null
		}

		async setup_async() {
			const identity = this.identity()
			try {
				await identity.onboard_http( this.hub_url().trim(), this.invite_code().trim() )
				this.invite_code( '' )
				this.controller().phase('idle')
			} catch( error ) {
				this.controller().phase('failed')
				this.controller().message(`Не удалось настроить устройство: ${(error as Error).message}`)
			}
		}

		override demo_setup( next?: Event ): null {
			if( next === undefined ) return null
			this.$.$mol_wire_async( this ).demo_setup_async()
			return null
		}

		async demo_setup_async() {
			const identity = this.identity()
			const key = await identity.ensure_device_keypair()
			const hub = this.$.$attendpro_transport_demo_hub.instance()
			const demo = await hub.onboard_demo( key.public_raw )
			identity.bundle({
				device_priv_b64u: await key.export_pkcs8(),
				device_pub_b64u: key.public_raw,
				credential: demo.credential,
				credential_hash: demo.credential_hash,
				university_public_raw: demo.university_public_raw,
				teacher_cred: demo.teacher_cred,
				hub_url: '',
				demo: true,
			} )
			this.controller().demo_mode( true )
		}

		// ── history ──────────────────────────────────────────────────────

		override history_rows() {
			return this.evidence().records().map( ( record, index ) => this.Record( index ) )
		}

		record( index: number ) {
			return this.evidence().records()[ index ]
		}

		override record_title( index: number ): string {
			const record = this.record( index )!
			const when = new Date( record.received_at * 1000 )
			const hh = String( when.getHours() ).padStart( 2, '0' )
			const mm = String( when.getMinutes() ).padStart( 2, '0' )
			return `${ record.session_name } · ${ hh }:${ mm }`
		}

		override record_state( index: number ): string {
			const record = this.record( index )!
			if( record.receipt ) {
				const body = record.receipt.body as unknown as $attendpro_protocol_receipt_body
				return `✓ Принято преподавателем · квитанция №${ body.receive_seq }`
			}
			return '⏳ Сохранено локально, квитанции пока нет'
		}

		override record_details( index: number ): string {
			const record = this.record( index )!
			return `mark ${ record.mark_hash.slice( 0, 12 ) }… · epoch ${ ( record.anchor.body as unknown as $attendpro_protocol_anchor_body ).epoch_index }`
		}

		override record_type( index: number ): string {
			return this.record( index )!.receipt ? 'success' : 'warn'
		}

		// ── header badges ────────────────────────────────────────────────

		override identity_line(): string {
			const bundle = this.identity().bundle()
			if( ! bundle ) return 'Устройство не настроено'
			const body = bundle.credential.body as unknown as $attendpro_protocol_device_cred_body
			return `${ body.student_name } · ${ bundle.demo ? 'демо' : body.university_id }`
		}

		override transport_line(): string {
			return `Радио: ${ this.controller().transport_label() }`
		}

		// ── reset ────────────────────────────────────────────────────────

		override reset( next?: Event ): null {
			if( next === undefined || this.controller().busy() ) return null
			this.identity().forget()
			this.evidence().reset()
			this.controller().demo_mode( false )
			this.controller().phase( 'idle' )
			this.controller().message( '' )
			return null
		}

	}

	export class $attendpro_student_record extends $.$attendpro_student_record {}

}
