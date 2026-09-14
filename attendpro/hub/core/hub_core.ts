namespace $ {

	// Pure hub logic: anchor epochs, mark admission, receipts, witness batch.
	// Runs unchanged in the Node hub (bleno + fs around it) and inside the
	// web app demo mode. No timers, no IO — callers drive time and transport.

	export type $attendpro_hub_core_invite = {
		code : string
		student_name : string
		used : boolean
	}

	export type $attendpro_hub_core_accepted = {
		mark_hash : string
		credential_hash : string
		student_name : string
		epoch_index : number
		receive_seq : number
		receipt : $attendpro_protocol_envelope
		mark : $attendpro_protocol_envelope
	}

	export type $attendpro_hub_core_reject = {
		reason : string
	}

	export type $attendpro_hub_core_identity = {
		university_private : CryptoKey
		university_public : CryptoKey
		university_public_raw : string
		hub_private : CryptoKey
		hub_public : CryptoKey
		hub_public_raw : string
		hub_key_id : string
		teacher_cred : $attendpro_protocol_envelope
	}

	export class $attendpro_hub_core {

		identity: $attendpro_hub_core_identity
		now: () => number = () => Math.floor( Date.now() / 1000 )

		invites: $attendpro_hub_core_invite[] = []
		device_creds = new Map< string, $attendpro_protocol_envelope >() // credential_hash -> env

		session_name = ''
		session_id = ''
		policy_hash = '00000000000000000000000000000000'
		anchors: { envelope: $attendpro_protocol_envelope, hash: string }[] = []
		accepted: $attendpro_hub_core_accepted[] = []
		closed = false

		private queue: Promise<unknown> = Promise.resolve()
		private serial<T>( action: () => Promise<T> ): Promise<T> {
			const result = this.queue.then( action )
			this.queue = result.catch( () => {} )
			return result
		}
		onboard( code: string, key: string ) { return this.serial( () => this.onboard_inner( code, key ) ) }
		session_start( name: string ) { return this.serial( () => this.session_start_inner( name ) ) }
		epoch_rotate() { return this.serial( () => this.epoch_rotate_inner() ) }
		accept_mark( mark: $attendpro_protocol_envelope ) { return this.serial( () => this.accept_mark_inner( mark ) ) }
		session_close() { return this.serial( () => this.session_close_inner() ) }

		constructor( identity: $attendpro_hub_core_identity ) {
			this.identity = identity
		}

		static async bootstrap(
			university_id: string,
			teacher_name: string,
		): Promise<{ core_factory: () => Promise<$attendpro_hub_core>, identity: $attendpro_hub_core_identity }> {
			// dev-mode SSO: the hub itself acts as the university identity authority (MVP shortcut)
			const university = await $attendpro_protocol_key_generate()
			const hub = await $attendpro_protocol_key_generate()
			const identity: $attendpro_hub_core_identity = {
				university_private: university.private_key,
				university_public: university.public_key,
				university_public_raw: university.public_raw,
				hub_private: hub.private_key,
				hub_public: hub.public_key,
				hub_public_raw: hub.public_raw,
				hub_key_id: await $attendpro_protocol_key_id( hub.public_raw ),
				teacher_cred: null!,
			}
			const now = Math.floor( Date.now() / 1000 )
			const teacher = await $attendpro_protocol_issue_teacher_cred(
				university.private_key, `${ university_id }/teacher/1`, teacher_name,
				hub.public_raw, now, now + 366 * 24 * 3600,
			)
			identity.teacher_cred = teacher.envelope
			return {
				identity,
				core_factory: async () => new $attendpro_hub_core( identity ),
			}
		}

		// ── invites & onboarding (dev SSO) ────────────────────────────────

		invite_create( student_name: string ): $attendpro_hub_core_invite {
			const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
			let code = ''
			for( let i = 0; i < 6; ++ i ) code += alphabet[ $attendpro_protocol_random( 1 )[0]! % alphabet.length ]
			const invite: $attendpro_hub_core_invite = { code, student_name, used: false }
			this.invites.push( invite )
			return invite
		}

		// replaces any previous invite with this code (demo mode reuses a fixed code)
		invite_reset( code: string, student_name: string ): $attendpro_hub_core_invite {
			this.invites = this.invites.filter( invite => invite.code !== code )
			const invite: $attendpro_hub_core_invite = { code, student_name, used: false }
			this.invites.push( invite )
			return invite
		}

		private async onboard_inner( code: string, device_pubkey_b64u: string ): Promise<{ credential: $attendpro_protocol_envelope, credential_hash: string, university_public_raw: string, teacher_cred: $attendpro_protocol_envelope }> {
			const invite = this.invites.find( i => i.code === code.toUpperCase() )
			if( ! invite ) throw new Error( 'UNKNOWN_INVITE' )
			if( invite.used ) throw new Error( 'INVITE_ALREADY_USED' )
			await $attendpro_protocol_key_import_public( device_pubkey_b64u )
			const now = this.now()
			const issued = await $attendpro_protocol_issue_device_cred(
				this.identity.university_private,
				'cit', invite.student_name, device_pubkey_b64u,
				now, now + 180 * 24 * 3600,
			)
			invite.used = true
			const hash = await $attendpro_protocol_hash_of_envelope( issued.envelope )
			this.device_creds.set( hash, issued.envelope )
			return {
				credential: issued.envelope,
				credential_hash: hash,
				university_public_raw: this.identity.university_public_raw,
				teacher_cred: this.identity.teacher_cred,
			}
		}

		// ── session & epochs ──────────────────────────────────────────────

		private async session_start_inner( session_name: string ): Promise<{ envelope: $attendpro_protocol_envelope, hash: string }> {
			if( this.anchors.length ) throw new Error( 'SESSION_ALREADY_STARTED' )
			this.session_name = session_name
			this.session_id = $attendpro_protocol_hex( $attendpro_protocol_random( 8 ) )
			return await this.epoch_issue( 0, '' )
		}

		private async epoch_rotate_inner(): Promise<{ envelope: $attendpro_protocol_envelope, hash: string }> {
			if( ! this.anchors.length ) throw new Error( 'NO_SESSION' )
			if( this.closed ) throw new Error( 'SESSION_CLOSED' )
			const last = this.anchors[ this.anchors.length - 1 ]!
			return await this.epoch_issue( ( last.envelope.body as unknown as $attendpro_protocol_anchor_body ).epoch_index + 1, last.hash )
		}

		private async epoch_issue( epoch_index: number, prev_anchor_hash: string ): Promise<{ envelope: $attendpro_protocol_envelope, hash: string }> {
			const body: $attendpro_protocol_anchor_body = {
				session_id: this.session_id,
				session_name: this.session_name,
				epoch_index,
				epoch_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
				prev_anchor_hash,
				hub_key_id: this.identity.hub_key_id,
				policy_hash: this.policy_hash,
				closing: false,
			}
			const sealed = await $attendpro_protocol_seal( 'anchor', body as unknown as $attendpro_protocol_fact_body, this.identity.hub_private )
			this.anchors.push( sealed )
			return sealed
		}

		anchor_current(): { envelope: $attendpro_protocol_envelope, hash: string } {
			if( ! this.anchors.length ) throw new Error( 'NO_SESSION' )
			return this.anchors[ this.anchors.length - 1 ]!
		}

		// ── mark admission (§8.4 steps 6-7) ──────────────────────────────

		private async accept_mark_inner( mark: $attendpro_protocol_envelope ): Promise<{ accepted?: $attendpro_hub_core_accepted, rejected?: $attendpro_hub_core_reject }> {

			if( this.closed ) return { rejected: { reason: 'SESSION_CLOSED' } }
			if( mark.kind !== 'mark' ) return { rejected: { reason: 'NOT_MARK' } }

			const body = mark.body as unknown as $attendpro_protocol_mark_body
			const anchor = this.anchor_current()
			const anchor_body = anchor.envelope.body as unknown as $attendpro_protocol_anchor_body



			// admission by credential snapshot (offline check, §8.2 step 4)
			const cred = this.device_creds.get( body.credential_hash )
			if( ! cred ) return { rejected: { reason: 'NO_CREDENTIAL' } }
			const cred_body = cred.body as unknown as $attendpro_protocol_device_cred_body

			// device key must have signed this exact mark
			const device_public = await $attendpro_protocol_key_import_public( cred_body.device_pubkey )
			const opened = await $attendpro_protocol_open( mark, device_public )
			if( ! opened.ok ) return { rejected: { reason: opened.reason! } }

			const previous = this.accepted.find( a => a.mark_hash === opened.hash )
			if( previous ) return { accepted: previous }
			if( body.anchor_hash !== anchor.hash ) return { rejected: { reason: 'STALE_ANCHOR' } }

			// credential validity window per hub clock (student clocks never matter)
			const now = this.now()
			if( now < cred_body.valid_from ) return { rejected: { reason: 'CREDENTIAL_NOT_YET_VALID' } }
			if( now > cred_body.valid_until ) return { rejected: { reason: 'CREDENTIAL_EXPIRED' } }

			// duplicate: one mark per credential per session
			if( this.accepted.some( a => a.credential_hash === body.credential_hash ) ) {
				return { rejected: { reason: 'DUPLICATE' } }
			}

			const mark_hash = opened.hash!
			const receive_seq = this.accepted.length + 1
			const receipt = await $attendpro_protocol_seal( 'receipt', {
				mark_hash,
				anchor_hash: anchor.hash,
				receive_seq,
				epoch_state: 'open',
			}, this.identity.hub_private )

			const record: $attendpro_hub_core_accepted = {
				mark,
				mark_hash,
				credential_hash: body.credential_hash,
				student_name: cred_body.student_name,
				epoch_index: anchor_body.epoch_index,
				receive_seq,
				receipt: receipt.envelope,
			}
			this.accepted.push( record )
			return { accepted: record }
		}

		// ── closing (§8.6) ────────────────────────────────────────────────

		private async session_close_inner(): Promise<{ final_anchor: { envelope: $attendpro_protocol_envelope, hash: string }, batch: { envelope: $attendpro_protocol_envelope, hash: string } }> {
			if( ! this.anchors.length ) throw new Error( 'NO_SESSION' )
			if( this.closed ) throw new Error( 'SESSION_CLOSED' )
			this.closed = true

			const last = this.anchors[ this.anchors.length - 1 ]!
			const last_body = last.envelope.body as unknown as $attendpro_protocol_anchor_body
			const final_body: $attendpro_protocol_anchor_body = {
				... last_body,
				epoch_index: last_body.epoch_index + 1,
				epoch_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
				prev_anchor_hash: last.hash,
				closing: true,
			}
			const final_anchor = await $attendpro_protocol_seal( 'anchor', final_body as unknown as $attendpro_protocol_fact_body, this.identity.hub_private )
			this.anchors.push( final_anchor )

			const merkle_root = await $attendpro_protocol_merkle_root( this.accepted.map( a => a.mark_hash ) )
			const batch = await $attendpro_protocol_seal( 'batch', {
				session_id: this.session_id,
				final_epoch_index: final_body.epoch_index,
				merkle_root,
				count: this.accepted.length,
				final_receive_seq: this.accepted.length,
				prev_batch_hash: '',
			}, this.identity.hub_private )

			return { final_anchor, batch }
		}

	}

}
