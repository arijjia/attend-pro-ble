namespace $ {

	// Local evidence of the student (§8.8): own Marks, hub Receipts, observed Anchors.
	// MVP keeps them in localStorage as an append-only list of self-sufficient
	// signed envelopes — the store is replaceable (concept §10.5) without
	// touching the proof layer.

	export type $attendpro_evidence_record = {
		session_id : string
		session_name : string
		mark : $attendpro_protocol_envelope
		mark_hash : string
		anchor : $attendpro_protocol_envelope
		receipt : $attendpro_protocol_envelope | null
		received_at : number // unix seconds, informational only — proves nothing
	}

	export class $attendpro_evidence extends $mol_object {

		records_key = 'attendpro.evidence'

		@ $mol_mem
		records( next?: $attendpro_evidence_record[] ): $attendpro_evidence_record[] {
			return this.$.$mol_store_local.value( this.records_key, next ) ?? []
		}

		append( record: $attendpro_evidence_record ) {
			this.records([ ... this.records(), record ])
		}

		attach_receipt( mark_hash: string, receipt: $attendpro_protocol_envelope ) {
			this.records( this.records().map( record =>
				record.mark_hash === mark_hash ? { ... record, receipt } : record,
			) )
		}

		has_mark_for( session_id: string ) {
			return this.records().some( record => record.session_id === session_id )
		}

		reset() {
			this.records( [] )
		}

		// offline "спор" bundle: everything a verifier needs to re-check one mark
		export_bundle( index: number, device_cred: $attendpro_protocol_envelope ): string {
			const record = this.records()[ index ]
			if( ! record ) return ''
			return JSON.stringify({
				mark: record.mark,
				receipt: record.receipt,
				anchor: record.anchor,
				device_cred,
			}, null, '\t' )
		}

	}

}
