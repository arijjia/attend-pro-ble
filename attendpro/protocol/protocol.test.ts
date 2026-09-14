namespace $ {

	$mol_test({

		async 'base64url roundtrip'( $ ) {
			for( const size of [ 0, 1, 2, 3, 4, 63, 64, 65 ] ) {
				const bytes = $attendpro_protocol_random( size )
				$mol_assert_equal(
					$attendpro_protocol_utf8_decode( $attendpro_protocol_b64u_decode( $attendpro_protocol_b64u_encode( bytes ) ) ),
					$attendpro_protocol_utf8_decode( bytes ),
				)
			}
			// RFC 4648 test vectors (base64url, no padding)
			$mol_assert_equal( $attendpro_protocol_b64u_encode( $attendpro_protocol_utf8_encode( 'foobar' ) ), 'Zm9vYmFy' )
			$mol_assert_equal( $attendpro_protocol_utf8_decode( $attendpro_protocol_b64u_decode( 'Zm9vYmFy' ) ), 'foobar' )
		} ,

		async 'hex roundtrip'( $ ) {
			const bytes = $attendpro_protocol_random( 32 )
			$mol_assert_equal(
				$attendpro_protocol_utf8_decode( $attendpro_protocol_unhex( $attendpro_protocol_hex( bytes ) ) ),
				$attendpro_protocol_utf8_decode( bytes ),
			)
		} ,

		async 'canonical json sorts keys recursively'( $ ) {
			$mol_assert_equal(
				$attendpro_protocol_canonical({ b: 1, a: { d: 'x', c: [ 3, 2 ] } }),
				'{"a":{"c":[3,2],"d":"x"},"b":1}',
			)
		} ,

		async 'canonical json rejects floats and undefined'( $ ) {
			let error = ''
			try { $attendpro_protocol_canonical({ x: 0.5 }) } catch( e ) { error = (e as Error).message }
			$mol_assert_ok( /non-integer/.test( error ) )
		} ,

		async 'sha256 known vector'( $ ) {
			$mol_assert_equal(
				await $attendpro_protocol_sha256_hex( 'abc' ),
				'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
			)
		} ,

		async 'es256 seal and open'( $ ) {
			const pair = await $attendpro_protocol_key_generate()
			const body = { session_id: 's1', epoch_index: 3, note: 'тест' }
			const sealed = await $attendpro_protocol_seal( 'anchor', body, pair.private_key )
			const public_key = await $attendpro_protocol_key_import_public( pair.public_raw )
			const opened = await $attendpro_protocol_open( sealed.envelope, public_key )
			$mol_assert_ok( opened.ok )
			$mol_assert_equal( opened.hash, sealed.hash )
			$mol_assert_equal( sealed.envelope.v, 1 )
			$mol_assert_equal( sealed.envelope.kind, 'anchor' )
		} ,

		async 'es256 tampered body fails'( $ ) {
			const pair = await $attendpro_protocol_key_generate()
			const sealed = await $attendpro_protocol_seal( 'mark', { anchor_hash: 'aa' }, pair.private_key )
			sealed.envelope.body.anchor_hash = 'bb'
			const public_key = await $attendpro_protocol_key_import_public( pair.public_raw )
			const opened = await $attendpro_protocol_open( sealed.envelope, public_key )
			$mol_assert_not( opened.ok )
			$mol_assert_equal( opened.reason, 'BAD_SIGNATURE' )
		} ,

		async 'fact encode/decode roundtrip'( $ ) {
			const pair = await $attendpro_protocol_key_generate()
			const sealed = await $attendpro_protocol_seal( 'receipt', { mark_hash: 'ff', receive_seq: 7 }, pair.private_key )
			const bytes = $attendpro_protocol_encode( sealed.envelope )
			const decoded = $attendpro_protocol_decode( bytes )
			$mol_assert_equal( decoded, sealed.envelope )
		} ,

		async 'private key restore gives same public raw'( $ ) {
			const pair = await $attendpro_protocol_key_generate()
			const pkcs8 = await crypto.subtle.exportKey( 'pkcs8', pair.private_key )
			const restored = await $attendpro_protocol_key_from_private( $attendpro_protocol_b64u_encode( new Uint8Array( pkcs8 ) ) )
			$mol_assert_equal( restored.public_raw, pair.public_raw )
		} ,

		async 'merkle root matches bitcoin-style vector'( $ ) {
			// leaves sha256('a'), sha256('b'), sha256('c') paired with odd-duplication on every level
			const leaves: string[] = []
			for( const s of [ 'a', 'b', 'c' ] ) leaves.push( await $attendpro_protocol_sha256_hex( s ) )
			const root = await $attendpro_protocol_merkle_root( leaves )
			const pair12 = $attendpro_protocol_hex( await $attendpro_protocol_sha256( $attendpro_protocol_concat( $attendpro_protocol_unhex( leaves[0]! ), $attendpro_protocol_unhex( leaves[1]! ) ) ) )
			const pair3dup = $attendpro_protocol_hex( await $attendpro_protocol_sha256( $attendpro_protocol_concat( $attendpro_protocol_unhex( leaves[2]! ), $attendpro_protocol_unhex( leaves[2]! ) ) ) )
			const expected = $attendpro_protocol_hex( await $attendpro_protocol_sha256( $attendpro_protocol_concat( $attendpro_protocol_unhex( pair12 ), $attendpro_protocol_unhex( pair3dup ) ) ) )
			$mol_assert_equal( root, expected )
		} ,

		async 'merkle proof verifies inclusion'( $ ) {
			const leaves: string[] = []
			for( const s of [ 'l0', 'l1', 'l2', 'l3', 'l4' ] ) leaves.push( await $attendpro_protocol_sha256_hex( s ) )
			for( let i = 0; i < leaves.length; ++ i ) {
				const proof = await $attendpro_protocol_merkle_proof( leaves, i )
				$mol_assert_equal( proof.root, await $attendpro_protocol_merkle_root( leaves ) )
				$mol_assert_equal( await $attendpro_protocol_merkle_verify( leaves[i]!, proof.path ), proof.root )
			}
		} ,

		async 'merkle proof detects exclusion'( $ ) {
			const leaves: string[] = []
			for( const s of [ 'l0', 'l1', 'l2' ] ) leaves.push( await $attendpro_protocol_sha256_hex( s ) )
			const proof = await $attendpro_protocol_merkle_proof( leaves, 0 )
			const foreign = await $attendpro_protocol_sha256_hex( 'not-a-leaf' )
			$mol_assert_not( ( await $attendpro_protocol_merkle_verify( foreign, proof.path ) ) === proof.root )
		} ,

		async 'ble chunking roundtrip'( $ ) {
			const message = $attendpro_protocol_random( 430 )
			const frames = $attendpro_protocol_ble_pack_chunks( message )
			$mol_assert_equal( frames.length, 24 )
			const assembler = $attendpro_protocol_ble_chunk_assembler()
			let assembled: Uint8Array | null = null
			for( const frame of frames ) { $mol_assert_ok( frame.length <= 20 ); assembled = assembler.fed( frame ) }
			$mol_assert_equal( $attendpro_protocol_hex( assembled! ), $attendpro_protocol_hex( message ) )

		} ,

		async 'ble single-byte message packs one frame'( $ ) {
			const frames = $attendpro_protocol_ble_pack_chunks( new Uint8Array([ 123 ]) )
			$mol_assert_equal( frames.length, 1 )
			const assembler = $attendpro_protocol_ble_chunk_assembler()
			$mol_assert_equal( assembler.fed( frames[0]! )![0], 123 )
		} ,

		async 'key id is stable 16-byte prefix of sha256'( $ ) {
			const pair = await $attendpro_protocol_key_generate()
			const id1 = await $attendpro_protocol_key_id( pair.public_raw )
			const id2 = await $attendpro_protocol_key_id( pair.public_raw )
			$mol_assert_equal( id1, id2 )
			$mol_assert_equal( id1.length, 32 )
		} ,

	} )

}
