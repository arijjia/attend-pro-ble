namespace $ {

	// Device identity of a student: key pair + university-signed credential (§8.1).
	// MVP storage is localStorage; production moves the private key into OS keystore.

	export type $attendpro_identity_bundle = {
		device_priv_b64u : string // pkcs8
		device_pub_b64u : string // raw point
		credential : $attendpro_protocol_envelope
		credential_hash : string
		university_public_raw : string
		teacher_cred : $attendpro_protocol_envelope
		hub_url : string
		demo : boolean
	}

	export class $attendpro_identity extends $mol_object {

		@ $mol_mem
		bundle( next?: $attendpro_identity_bundle | null ): $attendpro_identity_bundle | null {
			return this.$.$mol_store_local.value( 'attendpro.identity', next ) ?? null
		}

		@ $mol_mem
		keys( next?: { private_key: CryptoKey, public_key: CryptoKey, public_raw: string } | null ) {
			return next ?? null
		}

		async keys_of( bundle: $attendpro_identity_bundle ) {
			let keys = this.keys()
			if( keys && keys.public_raw === bundle.device_pub_b64u ) return keys
			keys = await $attendpro_protocol_key_from_private( bundle.device_priv_b64u )
			this.keys( keys )
			return keys
		}

		async ensure_device_keypair(): Promise<{ public_raw: string, export_pkcs8: () => Promise<string> }> {
			const existing = this.bundle()
			if( existing ) {
				const keys = await this.keys_of( existing )
				return {
					public_raw: existing.device_pub_b64u,
					export_pkcs8: async () => {
						const pkcs8 = await crypto.subtle.exportKey( 'pkcs8', keys.private_key )
						return $attendpro_protocol_b64u_encode( new Uint8Array( pkcs8 ) )
					},
				}
			}
			const generated = await $attendpro_protocol_key_generate()
			this.keys({ private_key: generated.private_key, public_key: generated.public_key, public_raw: generated.public_raw })
			return {
				public_raw: generated.public_raw,
				export_pkcs8: async () => {
					const pkcs8 = await crypto.subtle.exportKey( 'pkcs8', generated.private_key )
					return $attendpro_protocol_b64u_encode( new Uint8Array( pkcs8 ) )
				},
			}
		}

		// Online onboarding against the hub's dev-SSO endpoint (§8.1, MVP version):
		// invite code from the teacher console + freshly generated device public key.
		async onboard_http( hub_url: string, code: string ): Promise<$attendpro_identity_bundle> {
			const key = await this.ensure_device_keypair()
			const priv_b64u = await key.export_pkcs8()
			const response = await fetch( `${ hub_url.replace( /\/+$/, '' ) }/api/onboard`, {
				method: 'POST',
				signal: AbortSignal.timeout(15000),
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ code, pubkey: key.public_raw }),
			} )
			if( ! response.ok ) throw new Error( `ONBOARD_HTTP_${ response.status }` )
			const data = await response.json() as {
				credential: $attendpro_protocol_envelope
				credential_hash: string
				university_public_raw: string
				teacher_cred: $attendpro_protocol_envelope
			}
			const authority = await $attendpro_protocol_key_import_public(data.university_public_raw)
			const cred = data.credential.body as unknown as $attendpro_protocol_device_cred_body
			const teacher = data.teacher_cred.body as unknown as $attendpro_protocol_teacher_cred_body
			if( data.credential.kind !== 'device_cred' || data.teacher_cred.kind !== 'teacher_cred' || teacher.role !== 'teacher'
				|| cred.device_pubkey !== key.public_raw
				|| !(await $attendpro_protocol_open(data.credential, authority)).ok
				|| !(await $attendpro_protocol_open(data.teacher_cred, authority)).ok
				|| await $attendpro_protocol_hash_of_envelope(data.credential) !== data.credential_hash ) throw new Error('INVALID_ONBOARDING_RESPONSE')
			const bundle: $attendpro_identity_bundle = {
				device_priv_b64u: priv_b64u,
				device_pub_b64u: key.public_raw,
				credential: data.credential,
				credential_hash: data.credential_hash,
				university_public_raw: data.university_public_raw,
				teacher_cred: data.teacher_cred,
				hub_url,
				demo: false,
			}
			this.bundle( bundle )
			return bundle
		}

		forget() {
			this.bundle( null )
			this.keys( null )
		}

	}

}
