namespace $ {

	$mol_test({

		async 'session start issues epoch 0 anchor chained to nothing'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'Преподаватель' )
			const core = await core_factory()
			await core.session_start( 'Алгоритмы' )
			const anchor = core.anchor_current()
			const body = anchor.envelope.body as unknown as $attendpro_protocol_anchor_body
			$mol_assert_equal( body.epoch_index, 0 )
			$mol_assert_equal( body.prev_anchor_hash, '' )
			$mol_assert_equal( body.session_name, 'Алгоритмы' )
			$mol_assert_equal( body.hub_key_id, core.identity.hub_key_id )
		} ,

		async 'epoch rotation chains prev anchor hash'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'T' )
			const core = await core_factory()
			await core.session_start( 's' )
			const first = core.anchor_current()
			const second = await core.epoch_rotate()
			const body = second.envelope.body as unknown as $attendpro_protocol_anchor_body
			$mol_assert_equal( body.epoch_index, 1 )
			$mol_assert_equal( body.prev_anchor_hash, first.hash )
			$mol_assert_unique( body.epoch_nonce, ( first.envelope.body as unknown as $attendpro_protocol_anchor_body ).epoch_nonce )
		} ,

		async 'student onboards with invite and marks once'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'T' )
			const core = await core_factory()
			const invite = core.invite_create( 'Иванов' )
			const device = await $attendpro_protocol_key_generate()
			const onboarded = await core.onboard( invite.code, device.public_raw )

			await core.session_start( 'Алгоритмы' )
			const anchor = core.anchor_current()

			const mark = await $attendpro_protocol_seal( 'mark', {
				anchor_hash: anchor.hash,
				credential_hash: onboarded.credential_hash,
				mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
			}, device.private_key )

			const result = await core.accept_mark( mark.envelope )
			$mol_assert_ok( result.accepted )
			$mol_assert_equal( result.accepted!.student_name, 'Иванов' )
			$mol_assert_equal( result.accepted!.receive_seq, 1 )
			$mol_assert_equal( core.accepted.length, 1 )
		} ,

		async 'duplicate mark from same credential rejected'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'T' )
			const core = await core_factory()
			const invite = core.invite_create( 'Петров' )
			const device = await $attendpro_protocol_key_generate()
			const onboarded = await core.onboard( invite.code, device.public_raw )
			await core.session_start( 's' )
			const anchor = core.anchor_current()

			const mark_body = {
				anchor_hash: anchor.hash,
				credential_hash: onboarded.credential_hash,
				mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
			}
			const first = await core.accept_mark(( await $attendpro_protocol_seal( 'mark', mark_body, device.private_key ) ).envelope )
			const second = await core.accept_mark(( await $attendpro_protocol_seal( 'mark', { ... mark_body, mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ) }, device.private_key ) ).envelope )
			$mol_assert_ok( first.accepted )
			$mol_assert_equal( second.rejected!.reason, 'DUPLICATE' )
		} ,

		async 'mark with stale anchor rejected after rotation'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'T' )
			const core = await core_factory()
			const invite = core.invite_create( 'Сидоров' )
			const device = await $attendpro_protocol_key_generate()
			const onboarded = await core.onboard( invite.code, device.public_raw )
			await core.session_start( 's' )
			const stale = core.anchor_current()
			await core.epoch_rotate()

			const mark = await $attendpro_protocol_seal( 'mark', {
				anchor_hash: stale.hash,
				credential_hash: onboarded.credential_hash,
				mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
			}, device.private_key )
			const result = await core.accept_mark( mark.envelope )
			$mol_assert_equal( result.rejected!.reason, 'STALE_ANCHOR' )
		} ,

		async 'mark signed by wrong key rejected'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'T' )
			const core = await core_factory()
			const invite = core.invite_create( 'Хакер' )
			const honest = await $attendpro_protocol_key_generate()
			const imposter = await $attendpro_protocol_key_generate()
			const onboarded = await core.onboard( invite.code, honest.public_raw )
			await core.session_start( 's' )
			const anchor = core.anchor_current()

			const mark = await $attendpro_protocol_seal( 'mark', {
				anchor_hash: anchor.hash,
				credential_hash: onboarded.credential_hash,
				mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
			}, imposter.private_key )
			const result = await core.accept_mark( mark.envelope )
			$mol_assert_equal( result.rejected!.reason, 'BAD_SIGNATURE' )
		} ,

		async 'mark without onboarded credential rejected'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'T' )
			const core = await core_factory()
			const stranger = await $attendpro_protocol_key_generate()
			await core.session_start( 's' )
			const anchor = core.anchor_current()

			const fake_hash = await $attendpro_protocol_sha256_hex( 'nope' )
			const mark = await $attendpro_protocol_seal( 'mark', {
				anchor_hash: anchor.hash,
				credential_hash: fake_hash,
				mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
			}, stranger.private_key )
			const result = await core.accept_mark( mark.envelope )
			$mol_assert_equal( result.rejected!.reason, 'NO_CREDENTIAL' )
		} ,

		async 'expired credential rejected by hub clock'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'T' )
			const core = await core_factory()
			const invite = core.invite_create( 'Опоздавший' )
			const device = await $attendpro_protocol_key_generate()
			const onboarded = await core.onboard( invite.code, device.public_raw )

			// travel 200 days into the future (credential valid for 180 days)
			core.now = () => Math.floor( Date.now() / 1000 ) + 200 * 24 * 3600
			await core.session_start( 's' )
			const anchor = core.anchor_current()

			const mark = await $attendpro_protocol_seal( 'mark', {
				anchor_hash: anchor.hash,
				credential_hash: onboarded.credential_hash,
				mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
			}, device.private_key )
			const result = await core.accept_mark( mark.envelope )
			$mol_assert_equal( result.rejected!.reason, 'CREDENTIAL_EXPIRED' )
		} ,

		async 'closing issues final anchor and witness batch with merkle root'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'T' )
			const core = await core_factory()
			const students = [ 'А', 'Б', 'В' ]
			const devices = [] as Awaited< ReturnType< typeof $attendpro_protocol_key_generate > >[]
			const creds = [] as string[]
			for( const name of students ) {
				const invite = core.invite_create( name )
				const device = await $attendpro_protocol_key_generate()
				creds.push(( await core.onboard( invite.code, device.public_raw ) ).credential_hash )
				devices.push( device )
			}
			await core.session_start( 'Пара' )
			const anchor = core.anchor_current()
			for( let i = 0; i < students.length; ++ i ) {
				const mark = await $attendpro_protocol_seal( 'mark', {
					anchor_hash: anchor.hash,
					credential_hash: creds[i]!,
					mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
				}, devices[i]!.private_key )
				const result = await core.accept_mark( mark.envelope )
				$mol_assert_ok( result.accepted )
			}

			const { final_anchor, batch } = await core.session_close()
			const final_body = final_anchor.envelope.body as unknown as $attendpro_protocol_anchor_body
			$mol_assert_ok( final_body.closing )
			const batch_body = batch.envelope.body as unknown as $attendpro_protocol_batch_body
			$mol_assert_equal( batch_body.count, 3 )
			$mol_assert_equal( batch_body.final_receive_seq, 3 )
			$mol_assert_equal( batch_body.merkle_root, await $attendpro_protocol_merkle_root( core.accepted.map( a => a.mark_hash ) ) )
			$mol_assert_ok( batch_body.merkle_root !== '' )

			// marks are no longer accepted after close
			const late = await $attendpro_protocol_seal( 'mark', {
				anchor_hash: anchor.hash,
				credential_hash: creds[0]!,
				mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
			}, devices[0]!.private_key )
			const result = await core.accept_mark( late.envelope )
			$mol_assert_equal( result.rejected!.reason, 'SESSION_CLOSED' )
		} ,

		async 'invite cannot be reused'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'T' )
			const core = await core_factory()
			const invite = core.invite_create( 'X' )
			const first_device = await $attendpro_protocol_key_generate()
			const second_device = await $attendpro_protocol_key_generate()
			await core.onboard( invite.code, first_device.public_raw )
			let error = ''
			try { await core.onboard( invite.code, second_device.public_raw ) } catch( e ) { error = (e as Error).message }
			$mol_assert_equal( error, 'INVITE_ALREADY_USED' )
		} ,

		async 'zero-trust evidence verification passes for honest set'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'T' )
			const core = await core_factory()
			const invite = core.invite_create( 'Честный' )
			const device = await $attendpro_protocol_key_generate()
			const onboarded = await core.onboard( invite.code, device.public_raw )
			await core.session_start( 's' )
			const anchor = core.anchor_current()

			const mark = await $attendpro_protocol_seal( 'mark', {
				anchor_hash: anchor.hash,
				credential_hash: onboarded.credential_hash,
				mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
			}, device.private_key )
			const result = await core.accept_mark( mark.envelope )
			const closed = await core.session_close()

			const verdict = await $attendpro_protocol_verify_evidence({
				mark: mark.envelope,
				receipt: result.accepted!.receipt,
				device_cred: onboarded.credential,
				anchor: anchor.envelope,
				batch: closed.batch.envelope,
			}, core.identity.university_public, core.identity.hub_public, Math.floor( Date.now() / 1000 ) )
			$mol_assert_equal( verdict.ok, verdict.reasons.length === 0 )
		} ,

		async 'zero-trust evidence verification catches fake receipt'( $ ) {
			const { core_factory } = await $attendpro_hub_core.bootstrap( 'cit', 'T' )
			const core = await core_factory()
			const invite = core.invite_create( 'Жертва' )
			const device = await $attendpro_protocol_key_generate()
			const onboarded = await core.onboard( invite.code, device.public_raw )
			await core.session_start( 's' )
			const anchor = core.anchor_current()

			const mark = await $attendpro_protocol_seal( 'mark', {
				anchor_hash: anchor.hash,
				credential_hash: onboarded.credential_hash,
				mark_nonce: $attendpro_protocol_hex( $attendpro_protocol_random( 16 ) ),
			}, device.private_key )
			await core.accept_mark( mark.envelope )

			// attacker hub key forges a receipt
			const attacker = await $attendpro_protocol_key_generate()
			const mark_hash = await $attendpro_protocol_hash_of_envelope( mark.envelope )
			const fake_receipt = await $attendpro_protocol_seal( 'receipt', {
				mark_hash,
				anchor_hash: anchor.hash,
				receive_seq: 1,
				epoch_state: 'open',
			}, attacker.private_key )

			const verdict = await $attendpro_protocol_verify_evidence({
				mark: mark.envelope,
				receipt: fake_receipt.envelope,
				device_cred: onboarded.credential,
				anchor: anchor.envelope,
			}, core.identity.university_public, core.identity.hub_public, Math.floor( Date.now() / 1000 ) )
			$mol_assert_not( verdict.ok )
			$mol_assert_ok( verdict.reasons.includes( 'RECEIPT_BAD_SIGNATURE' ) )
		} ,

	} )

}
