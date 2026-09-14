namespace $ {

	// End-to-end student flow through the controller against the in-page demo hub:
	// the same code path the phone runs over real BLE, minus the radio.

	async function demo_onboard( identity: $attendpro_identity ) {
		const key = await identity.ensure_device_keypair()
		const hub = $attendpro_transport_demo_hub.instance()
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
	}

	$mol_test({

		async 'full demo mark flow reaches accepted with verified receipt'( $ ) {

			const identity = $.$attendpro_identity.make({ $ })
			const evidence = $.$attendpro_evidence.make({ $ })
			identity.bundle( null )
			evidence.reset()

			// no identity yet → clear refusal
			const controller = $.$attendpro_controller.make({ $, identity, transport_override: $attendpro_transport_demo_make({ scan_ms: 5, deliver_ms: 5 }), receipt_wait_ms: 300, scan_ms: 30 })
			await controller.mark( evidence )
			$mol_assert_equal( controller.phase(), 'no_identity' )

			// fresh demo hub session for this run
			$.$attendpro_transport_demo_hub.instance().core = null
			await demo_onboard( identity )

			await controller.mark( evidence )
			$mol_assert_equal( controller.phase(), 'accepted' )

			const records = evidence.records()
			$mol_assert_equal( records.length, 1 )
			$mol_assert_ok( records[0]!.receipt )

			// the stored evidence re-verifies cryptographically (zero-trust replay)
			const bundle = identity.bundle()!
			const verdict = await $attendpro_protocol_verify_evidence({
				mark: records[0]!.mark,
				receipt: records[0]!.receipt!,
				device_cred: bundle.credential,
				anchor: records[0]!.anchor,
			}, await $attendpro_protocol_key_import_public( bundle.university_public_raw ),
				await $attendpro_protocol_key_import_public(( bundle.teacher_cred.body as unknown as $attendpro_protocol_teacher_cred_body ).hub_pubkey ),
				Math.floor( Date.now() / 1000 ) )
			$mol_assert_equal( verdict.ok, verdict.reasons.length === 0 )
			$mol_assert_equal( verdict.ok, true )

			// second attempt on the same session → already marked, no second mark stored
			await controller.mark( evidence )
			$mol_assert_equal( controller.phase(), 'already_marked' )
			$mol_assert_equal( evidence.records().length, 1 )
		} ,

		async 'mark with foreign credential gets no receipt and times out'( $ ) {

			const identity = $.$attendpro_identity.make({ $ })
			const evidence = $.$attendpro_evidence.make({ $ })
			identity.bundle( null )
			evidence.reset()

			$.$attendpro_transport_demo_hub.instance().core = null
			await demo_onboard( identity )

			// sabotage: point the controller at a credential the hub never issued
			const bundle = identity.bundle()!
			identity.bundle({ ... bundle, credential_hash: await $attendpro_protocol_sha256_hex( 'foreign' ) })

			const controller = $.$attendpro_controller.make({ $, identity, transport_override: $attendpro_transport_demo_make({ scan_ms: 5, deliver_ms: 5 }), receipt_wait_ms: 250, scan_ms: 30 })
			await controller.mark( evidence )
			$mol_assert_equal( controller.phase(), 'receipt_timeout' )
			$mol_assert_equal( evidence.records()[0]!.receipt, null )
		} ,

	} )

}
