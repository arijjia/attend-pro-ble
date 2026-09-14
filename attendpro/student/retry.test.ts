namespace $ {
	$mol_test({
		async 'lost receipt retry preserves mark identity and persists immediate receipt'( $ ) {
			const identity = $.$attendpro_identity.make({ $ })
			const evidence = $.$attendpro_evidence.make({ $ })
			identity.forget(); evidence.reset()
			$attendpro_transport_demo_hub.instance().core = null
			const key = await identity.ensure_device_keypair()
			const issued = await $attendpro_transport_demo_hub.instance().onboard_demo(key.public_raw)
			identity.bundle({ ...issued, device_priv_b64u: await key.export_pkcs8(), device_pub_b64u: key.public_raw, hub_url: '', demo: true })
			const transport = $attendpro_transport_demo_make({ scan_ms: 0, deliver_ms: 0 })
			const subscribe = transport.subscribe_receipt
			transport.subscribe_receipt = async () => {}
			const controller = $.$attendpro_controller.make({ $, identity, transport_override: transport, receipt_wait_ms: 50 })
			await controller.mark(evidence)
			$mol_assert_equal(controller.phase(), 'receipt_timeout')
			const hash = evidence.records()[0]!.mark_hash
			transport.subscribe_receipt = subscribe
			await controller.mark(evidence)
			$mol_assert_equal(controller.phase(), 'accepted')
			$mol_assert_equal(evidence.records().length, 1)
			$mol_assert_equal(evidence.records()[0]!.mark_hash, hash)
			$mol_assert_ok(evidence.records()[0]!.receipt)
			const record = evidence.records()[0]!
			evidence.records([{ ...record, receipt: null }]); controller.phase('idle')
			const wrong = await $attendpro_protocol_seal('receipt', { mark_hash: hash, anchor_hash: 'wrong', epoch_state: 'open', receive_seq: 1 }, $attendpro_transport_demo_hub.instance().core!.identity.hub_private)
			await controller.receipt_incoming($attendpro_protocol_encode(wrong.envelope), hash, evidence)
			$mol_assert_equal(controller.phase(), 'idle')
			$mol_assert_equal(evidence.records()[0]!.receipt, null)
		},
	})
}
