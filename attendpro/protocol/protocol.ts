namespace $ {

	// ── bytes / strings ────────────────────────────────────────────────────

	const encoder = new TextEncoder()
	const decoder = new TextDecoder()

	export function $attendpro_protocol_utf8_encode( text: string ): Uint8Array {
		return encoder.encode( text )
	}

	export function $attendpro_protocol_utf8_decode( bytes: Uint8Array ): string {
		return decoder.decode( bytes )
	}

	export function $attendpro_protocol_concat( ... parts: Uint8Array[] ): Uint8Array {
		let size = 0
		for( const part of parts ) size += part.byteLength
		const out = new Uint8Array( size )
		let offset = 0
		for( const part of parts ) {
			out.set( part, offset )
			offset += part.byteLength
		}
		return out
	}

	export function $attendpro_protocol_random( bytes: number ): Uint8Array {
		const out = new Uint8Array( bytes )
		crypto.getRandomValues( out )
		return out
	}

	export function $attendpro_protocol_hex( bytes: Uint8Array ): string {
		let out = ''
		for( let i = 0; i < bytes.length; ++ i ) out += bytes[i]!.toString(16).padStart( 2, '0' )
		return out
	}

	const hex_digit = '0123456789abcdef'

	export function $attendpro_protocol_unhex( hex: string ): Uint8Array {
		if( hex.length % 2 ) throw new Error( `odd hex length: ${ hex.length }` )
		const out = new Uint8Array( hex.length / 2 )
		for( let i = 0; i < out.length; ++ i ) {
			const hi = hex_digit.indexOf( hex[ i * 2 ]!.toLowerCase() )
			const lo = hex_digit.indexOf( hex[ i * 2 + 1 ]!.toLowerCase() )
			if( hi < 0 || lo < 0 ) throw new Error( `bad hex char in: ${ hex.slice( i * 2, i * 2 + 2 ) }` )
			out[ i ] = hi * 16 + lo
		}
		return out
	}

	const b64u_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

	export function $attendpro_protocol_b64u_encode( bytes: Uint8Array ): string {
		let out = ''
		for( let i = 0; i < bytes.length; i += 3 ) {
			const b0 = bytes[i]!
			const b1 = bytes[ i + 1 ]
			const b2 = bytes[ i + 2 ]
			out += b64u_alphabet[ b0 >> 2 ]!
			out += b64u_alphabet[ ( b0 & 3 ) << 4 | ( b1 ? b1 >> 4 : 0 ) ]!
			if( b1 === undefined ) break
			out += b64u_alphabet[ ( b1 & 15 ) << 2 | ( b2 ? b2 >> 6 : 0 ) ]!
			if( b2 === undefined ) break
			out += b64u_alphabet[ b2 & 63 ]!
		}
		return out
	}

	export function $attendpro_protocol_b64u_decode( text: string ): Uint8Array {
		const map = new Map<string, number>()
		for( let i = 0; i < b64u_alphabet.length; ++ i ) map.set( b64u_alphabet[i]!, i )
		while( text.endsWith( '=' ) ) text = text.slice( 0, -1 )
		const out = new Uint8Array( Math.floor( text.length * 3 / 4 ) )
		let acc = 0
		let bits = 0
		let offset = 0
		for( const char of text ) {
			const digit = map.get( char )
			if( digit === undefined ) throw new Error( `bad base64url char: ${ char }` )
			acc = acc << 6 | digit
			bits += 6
			if( bits >= 8 ) {
				bits -= 8
				out[ offset ++ ] = acc >> bits & 255
			}
		}
		return out.subarray( 0, offset )
	}

	// ── canonical JSON (RFC 8785 subset: int/string/array/map only) ────────

	export function $attendpro_protocol_canonical( value: unknown ): string {
		if( value === null || typeof value === 'boolean' ) return JSON.stringify( value )
		if( typeof value === 'string' ) return JSON.stringify( value )
		if( typeof value === 'number' ) {
			if( ! Number.isSafeInteger( value ) ) throw new Error( `non-integer number in fact: ${ value }` )
			return String( value )
		}
		if( Array.isArray( value ) ) {
			return '[' + value.map( item => $attendpro_protocol_canonical( item ) ).join( ',' ) + ']'
		}
		if( typeof value === 'object' ) {
			const record = value as Record<string, unknown>
			const keys = Object.keys( record ).sort()
			return '{' + keys.map( key => {
				return JSON.stringify( key ) + ':' + $attendpro_protocol_canonical( record[ key ] )
			} ).join( ',' ) + '}'
		}
		throw new Error( `unsupported type in fact: ${ typeof value }` )
	}

	// ── hashing ────────────────────────────────────────────────────────────

	export async function $attendpro_protocol_sha256( bytes: Uint8Array ): Promise<Uint8Array> {
		const digest = await crypto.subtle.digest( 'SHA-256', bytes as unknown as ArrayBuffer )
		return new Uint8Array( digest )
	}

	export async function $attendpro_protocol_sha256_hex( text: string ): Promise<string> {
		return $attendpro_protocol_hex( await $attendpro_protocol_sha256( $attendpro_protocol_utf8_encode( text ) ) )
	}

	// ── ES256 keys (WebCrypto: browser + node >= 19) ───────────────────────

	export type $attendpro_protocol_key_pair = {
		private_key : CryptoKey
		public_key : CryptoKey
		public_raw : string // b64u of uncompressed point (65 bytes)
	}

	const subtle = () => crypto.subtle

	export async function $attendpro_protocol_key_generate(): Promise< $attendpro_protocol_key_pair > {
		const pair = await subtle().generateKey(
			{ name: 'ECDSA', namedCurve: 'P-256' } as EcKeyGenParams,
			true,
			[ 'sign', 'verify' ],
		) as CryptoKeyPair
		const raw = new Uint8Array( await subtle().exportKey( 'raw', pair.publicKey ) )
		return {
			private_key: pair.privateKey,
			public_key: pair.publicKey,
			public_raw: $attendpro_protocol_b64u_encode( raw ),
		}
	}

	export async function $attendpro_protocol_key_from_private( pkcs8_b64u: string ): Promise< $attendpro_protocol_key_pair > {
		const private_key = await subtle().importKey(
			'pkcs8',
			$attendpro_protocol_b64u_decode( pkcs8_b64u ) as unknown as ArrayBuffer,
			{ name: 'ECDSA', namedCurve: 'P-256' } as EcKeyImportParams,
			true,
			[ 'sign' ],
		)
		const public_key = await subtle().importKey(
			'raw',
			$attendpro_protocol_b64u_decode( await $attendpro_protocol_key_public_raw_of( private_key ) ) as unknown as ArrayBuffer,
			{ name: 'ECDSA', namedCurve: 'P-256' } as EcKeyImportParams,
			true,
			[ 'verify' ],
		)
		return {
			private_key,
			public_key,
			public_raw: await $attendpro_protocol_key_public_raw_of( private_key ),
		}
	}

	// EC private key PKCS8 contains the public point at the tail (uncompressed, 65 bytes, starts 0x04)
	async function $attendpro_protocol_key_public_raw_of( private_key: CryptoKey ): Promise<string> {
		const pkcs8 = new Uint8Array( await subtle().exportKey( 'pkcs8', private_key ) )
		const tail = pkcs8.slice( pkcs8.length - 65 )
		if( tail[0] !== 4 ) throw new Error( 'unexpected pkcs8 tail' )
		return $attendpro_protocol_b64u_encode( tail )
	}

	export async function $attendpro_protocol_key_import_public( public_raw_b64u: string ): Promise< CryptoKey > {
		return await subtle().importKey(
			'raw',
			$attendpro_protocol_b64u_decode( public_raw_b64u ) as unknown as ArrayBuffer,
			{ name: 'ECDSA', namedCurve: 'P-256' } as EcKeyImportParams,
			true,
			[ 'verify' ],
		)
	}

	export async function $attendpro_protocol_key_id( public_raw_b64u: string ): Promise<string> {
		return $attendpro_protocol_hex( ( await $attendpro_protocol_sha256( $attendpro_protocol_b64u_decode( public_raw_b64u ) ) ).slice( 0, 16 ) )
	}

	export async function $attendpro_protocol_sign( private_key: CryptoKey, bytes: Uint8Array ): Promise<Uint8Array> {
		const sig = await subtle().sign(
			{ name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
			private_key,
			bytes as unknown as ArrayBuffer,
		)
		// WebCrypto gives raw r||s (64 bytes) — convert to JWS/DER-less is fine,
		// but for interop we store IEEE P1363 raw signature (this exact form)
		return new Uint8Array( sig )
	}

	export async function $attendpro_protocol_verify( public_key: CryptoKey, signature: Uint8Array, bytes: Uint8Array ): Promise<boolean> {
		return await subtle().verify(
			{ name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
			public_key,
			signature as unknown as ArrayBuffer,
			bytes as unknown as ArrayBuffer,
		)
	}

	// ── fact envelope ──────────────────────────────────────────────────────

	export type $attendpro_protocol_fact_kind =
		| 'anchor'
		| 'mark'
		| 'receipt'
		| 'batch'
		| 'device_cred'
		| 'teacher_cred'
		| 'decision'

	export type $attendpro_protocol_fact_body = Record< string, string | number | boolean >

	export type $attendpro_protocol_envelope = {
		v : 1
		kind : $attendpro_protocol_fact_kind
		body : $attendpro_protocol_fact_body
		sig : string // b64u (raw P1363)
	}

	export type $attendpro_protocol_unsigned = {
		v : 1
		kind : $attendpro_protocol_fact_kind
		body : $attendpro_protocol_fact_body
	}

	const domain = $attendpro_protocol_utf8_encode( 'attendpro.fact.v1' )

	export function $attendpro_protocol_signing_bytes( kind: string, body: $attendpro_protocol_fact_body ): Uint8Array {
		return $attendpro_protocol_concat(
			domain,
			new Uint8Array([ 1 ]), // protocol version byte
			$attendpro_protocol_utf8_encode( kind ),
			new Uint8Array([ 0 ]), // kind terminator
			$attendpro_protocol_utf8_encode( $attendpro_protocol_canonical( body ) ),
		)
	}

	export function $attendpro_protocol_unsigned_view( env: $attendpro_protocol_envelope ): $attendpro_protocol_unsigned {
		return { v: 1, kind: env.kind, body: env.body }
	}

	export async function $attendpro_protocol_fact_hash( unsigned: $attendpro_protocol_unsigned ): Promise<string> {
		return await $attendpro_protocol_sha256_hex( $attendpro_protocol_canonical( unsigned ) )
	}

	export async function $attendpro_protocol_envelope_of( unsigned: $attendpro_protocol_unsigned, signature: Uint8Array ): Promise<$attendpro_protocol_envelope> {
		return {
			v: 1,
			kind: unsigned.kind,
			body: unsigned.body,
			sig: $attendpro_protocol_b64u_encode( signature ),
		}
	}

	export async function $attendpro_protocol_seal(
		kind: $attendpro_protocol_fact_kind,
		body: $attendpro_protocol_fact_body,
		private_key: CryptoKey,
	): Promise<{ envelope: $attendpro_protocol_envelope, hash: string }> {
		const signature = await $attendpro_protocol_sign( private_key, $attendpro_protocol_signing_bytes( kind, body ) )
		const envelope = await $attendpro_protocol_envelope_of({ v: 1, kind, body }, signature )
		return { envelope, hash: await $attendpro_protocol_fact_hash({ v: 1, kind, body }) }
	}

	export type $attendpro_protocol_check = {
		ok : boolean
		hash? : string
		reason? : string
	}

	export async function $attendpro_protocol_open( envelope: $attendpro_protocol_envelope, public_key: CryptoKey ): Promise<$attendpro_protocol_check> {
		const unsigned = $attendpro_protocol_unsigned_view( envelope )
		const hash = await $attendpro_protocol_fact_hash( unsigned )
		try {
			const ok = await $attendpro_protocol_verify( public_key, $attendpro_protocol_b64u_decode( envelope.sig ), $attendpro_protocol_signing_bytes( envelope.kind, envelope.body ) )
			return ok ? { ok: true, hash } : { ok: false, hash, reason: 'BAD_SIGNATURE' }
		} catch( error ) {
			return { ok: false, hash, reason: `SIGNATURE_ERROR:${ (error as Error).message }` }
		}
	}

	// wire format of facts: canonical utf8 json of the envelope
	export function $attendpro_protocol_encode( envelope: $attendpro_protocol_envelope ): Uint8Array {
		return $attendpro_protocol_utf8_encode( JSON.stringify( envelope ) )
	}

	export function $attendpro_protocol_decode( bytes: Uint8Array ): $attendpro_protocol_envelope {
		const envelope = JSON.parse( $attendpro_protocol_utf8_decode( bytes ) )
		if( envelope.v !== 1 ) throw new Error( `unsupported fact version: ${ envelope.v }` )
		if( typeof envelope.sig !== 'string' ) throw new Error( 'fact without signature' )
		return envelope
	}

	// ── merkle ─────────────────────────────────────────────────────────────

	// Standard merkle over hex-encoded leaf hashes: pair siblings, duplicate last on odd level.
	export async function $attendpro_protocol_merkle_root( leaves_hex: readonly string[] ): Promise<string> {
		if( leaves_hex.length === 0 ) return $attendpro_protocol_hex( await $attendpro_protocol_sha256( new Uint8Array(0) ) )
		let level = leaves_hex.map( leaf => $attendpro_protocol_unhex( leaf ) )
		while( level.length > 1 ) {
			const next: Uint8Array[] = []
			for( let i = 0; i < level.length; i += 2 ) {
				const left = level[i]!
				const right = level[ i + 1 ] ?? left
				next.push( await $attendpro_protocol_sha256( $attendpro_protocol_concat( left, right ) ) )
			}
			level = next
		}
		return $attendpro_protocol_hex( level[0]! )
	}

	export async function $attendpro_protocol_merkle_proof( leaves_hex: readonly string[], index: number ): Promise<{ root: string, path: { hash: string, side: 'L' | 'R' }[] }> {
		let level = leaves_hex.map( leaf => leaf )
		const path: { hash: string, side: 'L' | 'R' }[] = []
		let i = index
		while( level.length > 1 ) {
			const sibling_index = i % 2 === 0 ? Math.min( i + 1, level.length - 1 ) : i - 1
			const sibling_is_right = i % 2 === 0
			path.push({ hash: level[ sibling_index ]!, side: sibling_is_right ? 'R' : 'L' })
			const next: string[] = []
			for( let j = 0; j < level.length; j += 2 ) {
				const left = $attendpro_protocol_unhex( level[j]! )
				const right = $attendpro_protocol_unhex( level[ j + 1 ] ?? level[j]! )
				next.push( $attendpro_protocol_hex( await $attendpro_protocol_sha256( $attendpro_protocol_concat( left, right ) ) ) )
			}
			level = next
			i = Math.floor( i / 2 )
		}
		return { root: level[0]!, path }
	}

	export async function $attendpro_protocol_merkle_verify( leaf_hex: string, proof: readonly { hash: string, side: 'L' | 'R' }[] ): Promise<string> {
		let acc = leaf_hex
		for( const step of proof ) {
			const left = step.side === 'L' ? step.hash : acc
			const right = step.side === 'R' ? step.hash : acc
			acc = $attendpro_protocol_hex( await $attendpro_protocol_sha256( $attendpro_protocol_concat( $attendpro_protocol_unhex( left ), $attendpro_protocol_unhex( right ) ) ) )
		}
		return acc
	}

}
