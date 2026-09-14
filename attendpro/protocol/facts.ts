namespace $ {

	// Typed builders and verifiers for AttendPro v4 facts (see Docs/attendpro-ble-first-v4.md §4).

	// F1 · SessionAnchor — signed by hub
	export type $attendpro_protocol_anchor_body = {
		session_id : string
		session_name : string
		epoch_index : number
		epoch_nonce : string // hex, 16 bytes
		prev_anchor_hash : string // hex, "" for epoch 0
		hub_key_id : string // hex, 16 bytes
		policy_hash : string // hex, 16 bytes
		closing : boolean // true on the final anchor of a session
	}

	// F2 · Mark — signed by student device
	export type $attendpro_protocol_mark_body = {
		anchor_hash : string
		credential_hash : string
		mark_nonce : string // hex, 16 bytes
	}

	// F3 · Receipt — signed by hub
	export type $attendpro_protocol_receipt_body = {
		mark_hash : string
		anchor_hash : string
		receive_seq : number
		epoch_state : string // "open"
	}

	// F4 · WitnessBatch — signed by hub
	export type $attendpro_protocol_batch_body = {
		session_id : string
		final_epoch_index : number
		merkle_root : string
		count : number
		final_receive_seq : number
		prev_batch_hash : string // "" for the first batch
	}

	// F5 · DeviceCredential — signed by SSO validator (dev: hub)
	export type $attendpro_protocol_device_cred_body = {
		university_id : string
		student_name : string
		device_pubkey : string // b64u raw
		valid_from : number // unix seconds
		valid_until : number // unix seconds
		policy_version : number
	}

	// F6 · TeacherCredential — signed by SSO validator (dev: hub)
	export type $attendpro_protocol_teacher_cred_body = {
		teacher_id : string
		teacher_name : string
		hub_pubkey : string // b64u raw
		role : string // "teacher"
		scope : string // "*"
		valid_from : number
		valid_until : number
	}

	// F7 · Decision — signed by synchronizer
	export type $attendpro_protocol_decision_body = {
		mark_hash : string
		verdict : string // "accepted" | "rejected" | "needs_review"
		reason_codes : string // comma-separated (canonical bodies stay flat: int/string/bool only)
		policy_version : number
	}

	export async function $attendpro_protocol_hash_of_envelope( envelope: $attendpro_protocol_envelope ): Promise<string> {
		return await $attendpro_protocol_fact_hash( $attendpro_protocol_unsigned_view( envelope ) )
	}

	// ── credential issue / verify ──────────────────────────────────────────

	export async function $attendpro_protocol_issue_device_cred(
		signer_private: CryptoKey,
		university_id: string,
		student_name: string,
		device_pubkey: string,
		valid_from: number,
		valid_until: number,
	): Promise<{ envelope: $attendpro_protocol_envelope, hash: string }> {
		return await $attendpro_protocol_seal( 'device_cred', {
			university_id,
			student_name,
			device_pubkey,
			valid_from,
			valid_until,
			policy_version: 1,
		}, signer_private )
	}

	export async function $attendpro_protocol_issue_teacher_cred(
		signer_private: CryptoKey,
		teacher_id: string,
		teacher_name: string,
		hub_pubkey: string,
		valid_from: number,
		valid_until: number,
	): Promise<{ envelope: $attendpro_protocol_envelope, hash: string }> {
		return await $attendpro_protocol_seal( 'teacher_cred', {
			teacher_id,
			teacher_name,
			hub_pubkey,
			role: 'teacher',
			scope: '*',
			valid_from,
			valid_until,
		}, signer_private )
	}

	export type $attendpro_protocol_cred_check = {
		ok : boolean
		reason? : string
	}

	export async function $attendpro_protocol_check_device_cred(
		cred: $attendpro_protocol_envelope,
		university_public: CryptoKey,
		now_unix: number,
	): Promise<$attendpro_protocol_cred_check> {
		if( cred.kind !== 'device_cred' ) return { ok: false, reason: 'NOT_DEVICE_CRED' }
		const opened = await $attendpro_protocol_open( cred, university_public )
		if( ! opened.ok ) return { ok: false, reason: opened.reason }
		const body = cred.body as unknown as $attendpro_protocol_device_cred_body
		if( now_unix < body.valid_from ) return { ok: false, reason: 'CREDENTIAL_NOT_YET_VALID' }
		if( now_unix > body.valid_until ) return { ok: false, reason: 'CREDENTIAL_EXPIRED' }
		return { ok: true }
	}

	// ── student-side pre-mark verification (§8.4 step 4 — minimal local checks) ──

	export type $attendpro_protocol_anchor_check = {
		ok : boolean
		reason? : string
	}

	// Student verifies the anchor against the hub key certified by the university
	// (teacher credential chain), BEFORE creating a Mark (principle 3).
	export async function $attendpro_protocol_check_anchor_trusted(
		anchor: $attendpro_protocol_envelope,
		hub_public: CryptoKey,
		hub_key_id: string,
	): Promise<$attendpro_protocol_anchor_check> {
		if( anchor.kind !== 'anchor' ) return { ok: false, reason: 'NOT_ANCHOR' }
		const body = anchor.body as unknown as $attendpro_protocol_anchor_body
		if( body.hub_key_id !== hub_key_id ) return { ok: false, reason: 'HUB_KEY_MISMATCH' }
		if( body.closing ) return { ok: false, reason: 'EPOCH_CLOSED' }
		const opened = await $attendpro_protocol_open( anchor, hub_public )
		if( ! opened.ok ) return { ok: false, reason: opened.reason }
		return { ok: true }
	}

	// ── zero-trust re-verification of a full evidence set (§8.7 core) ───────

	export type $attendpro_protocol_evidence = {
		mark : $attendpro_protocol_envelope
		receipt : $attendpro_protocol_envelope
		device_cred : $attendpro_protocol_envelope
		anchor : $attendpro_protocol_envelope
		batch? : $attendpro_protocol_envelope
	}

	export type $attendpro_protocol_verdict = {
		ok : boolean
		reasons : string[]
		mark_hash : string
	}

	// Repeats every check itself (zero-trust to devices):
	// university→credential→device key→mark, hub key→anchor+receipt, field binding.
	export async function $attendpro_protocol_verify_evidence(
		evidence: $attendpro_protocol_evidence,
		university_public: CryptoKey,
		hub_public: CryptoKey,
		now_unix: number,
	): Promise<$attendpro_protocol_verdict> {

		const reasons: string[] = []
		const mark_hash = await $attendpro_protocol_hash_of_envelope( evidence.mark )

		if( evidence.mark.kind !== 'mark' ) reasons.push( 'NOT_MARK' )
		if( evidence.receipt.kind !== 'receipt' ) reasons.push( 'NOT_RECEIPT' )
		if( evidence.anchor.kind !== 'anchor' ) reasons.push( 'NOT_ANCHOR' )
		if( reasons.length ) return { ok: false, reasons, mark_hash }

		// 1. university signed the device credential, and it is valid
		const cred_check = await $attendpro_protocol_check_device_cred( evidence.device_cred, university_public, now_unix )
		if( ! cred_check.ok ) reasons.push( cred_check.reason! )

		// 2. certified device key signed the mark
		const cred_body = evidence.device_cred.body as unknown as $attendpro_protocol_device_cred_body
		const device_public = await $attendpro_protocol_key_import_public( cred_body.device_pubkey )
		const mark_open = await $attendpro_protocol_open( evidence.mark, device_public )
		if( ! mark_open.ok ) reasons.push( `MARK_${ mark_open.reason }` )

		// 3. certified hub key signed anchor and receipt
		const anchor_body = evidence.anchor.body as unknown as $attendpro_protocol_anchor_body
		const anchor_open = await $attendpro_protocol_open( evidence.anchor, hub_public )
		if( ! anchor_open.ok ) reasons.push( `ANCHOR_${ anchor_open.reason }` )
		const receipt_open = await $attendpro_protocol_open( evidence.receipt, hub_public )
		if( ! receipt_open.ok ) reasons.push( `RECEIPT_${ receipt_open.reason }` )

		// 4. mark references this credential and this anchor
		const mark_body = evidence.mark.body as unknown as $attendpro_protocol_mark_body
		const cred_hash = await $attendpro_protocol_hash_of_envelope( evidence.device_cred )
		if( mark_body.credential_hash !== cred_hash ) reasons.push( 'CREDENTIAL_HASH_MISMATCH' )
		const anchor_hash = await $attendpro_protocol_hash_of_envelope( evidence.anchor )
		if( mark_body.anchor_hash !== anchor_hash ) reasons.push( 'ANCHOR_HASH_MISMATCH' )

		// 5. receipt binds to this mark inside an open epoch of this session
		const receipt_body = evidence.receipt.body as unknown as $attendpro_protocol_receipt_body
		if( receipt_body.mark_hash !== mark_hash ) reasons.push( 'RECEIPT_MARK_MISMATCH' )
		if( receipt_body.anchor_hash !== anchor_hash ) reasons.push( 'RECEIPT_ANCHOR_MISMATCH' )
		if( receipt_body.epoch_state !== 'open' ) reasons.push( 'EPOCH_NOT_OPEN' )

		// 6. optional witness batch — must be about the same session
		if( evidence.batch ) {
			if( evidence.batch.kind !== 'batch' ) {
				reasons.push( 'NOT_BATCH' )
			} else {
				const batch_body = evidence.batch.body as unknown as $attendpro_protocol_batch_body
				if( batch_body.session_id !== anchor_body.session_id ) reasons.push( 'BATCH_SESSION_MISMATCH' )
				const batch_open = await $attendpro_protocol_open( evidence.batch, hub_public )
				if( ! batch_open.ok ) reasons.push( `BATCH_${ batch_open.reason }` )
			}
		}

		return { ok: reasons.length === 0, reasons, mark_hash }
	}

}
