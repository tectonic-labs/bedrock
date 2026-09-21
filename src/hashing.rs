//! Additional transport-neutral, unkeyed incremental hash primitives.
//!
//! Enable the optional `hashing` feature. SHA-256 and SHA-384 remain available
//! through the existing `symmetric` feature/module; their APIs are unchanged.
//! These primitives accept exact byte slices. Domains, file lengths, streaming
//! I/O and resource limits belong to callers, not this module.
//!
//! SHAKE exposes only the fixed prefixes named below, starting at output offset
//! zero. BLAKE2 uses unkeyed sequential mode, without salt or personalization.
//! BLAKE3 uses unkeyed hash mode, not keyed hash or derive-key mode.
//! Availability does not establish application-policy or CNSA compliance.
//!
//! ```
//! use tectonic_bedrock::hashing::{Sha512Context, sha512};
//! let mut context = Sha512Context::new();
//! context.update(b"first");
//! let snapshot = context.fork_finish();
//! context.update(b"second");
//! assert_eq!(snapshot, sha512(b"first"));
//! assert_eq!(context.finish(), sha512(b"firstsecond"));
//! ```

incremental_hash!(
    Sha512Context,
    Sha512Digest,
    sha512,
    sha2::Sha512,
    64,
    "SHA-512",
    sha2::Digest::update,
    |state: sha2::Sha512| sha2::Digest::finalize(state).into()
);
incremental_hash!(
    Sha3_256Context,
    Sha3_256Digest,
    sha3_256,
    sha3::Sha3_256,
    32,
    "SHA3-256",
    sha3::Digest::update,
    |state: sha3::Sha3_256| sha3::Digest::finalize(state).into()
);
incremental_hash!(
    Sha3_384Context,
    Sha3_384Digest,
    sha3_384,
    sha3::Sha3_384,
    48,
    "SHA3-384",
    sha3::Digest::update,
    |state: sha3::Sha3_384| sha3::Digest::finalize(state).into()
);
incremental_hash!(
    Shake128_256Context,
    Shake128_256Digest,
    shake128_256,
    shake::Shake128,
    32,
    "SHAKE128 (first 256 output bits)",
    shake::Update::update,
    |state: shake::Shake128| {
        let mut output = [0; 32];
        shake::XofReader::read(
            &mut shake::ExtendableOutput::finalize_xof(state),
            &mut output,
        );
        output
    }
);
incremental_hash!(
    Shake256_512Context,
    Shake256_512Digest,
    shake256_512,
    shake::Shake256,
    64,
    "SHAKE256 (first 512 output bits)",
    shake::Update::update,
    |state: shake::Shake256| {
        let mut output = [0; 64];
        shake::XofReader::read(
            &mut shake::ExtendableOutput::finalize_xof(state),
            &mut output,
        );
        output
    }
);
incremental_hash!(
    Blake2s256Context,
    Blake2s256Digest,
    blake2s256,
    blake2::Blake2s256,
    32,
    "BLAKE2s-256 (unkeyed sequential mode)",
    blake2::Digest::update,
    |state: blake2::Blake2s256| blake2::Digest::finalize(state).into()
);
incremental_hash!(
    Blake2b512Context,
    Blake2b512Digest,
    blake2b512,
    blake2::Blake2b512,
    64,
    "BLAKE2b-512 (unkeyed sequential mode)",
    blake2::Digest::update,
    |state: blake2::Blake2b512| blake2::Digest::finalize(state).into()
);
incremental_hash!(
    Blake3_256Context,
    Blake3_256Digest,
    blake3_256,
    blake3::Hasher,
    32,
    "BLAKE3 (unkeyed hash mode, first 256 output bits)",
    |state: &mut blake3::Hasher, data: &[u8]| {
        state.update(data);
    },
    |state: blake3::Hasher| *state.finalize().as_bytes()
);

#[cfg(test)]
mod tests {
    use super::*;

    // Pinned empty/abc and 2051-byte (i % 251) answers cross-checked using
    // Node.js crypto/OpenSSL independently of these Rust implementations.
    incremental_hash_tests!(
        sha512_vectors,
        Sha512Context,
        Sha512Digest,
        sha512,
        64,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "916df35ebff475189e6eb6b8d79c8da42a497e2ecc0350173f923ef823ed9507f33a05fbecdb3c79c9fcb8f9a3986466c47f971f24bf9d089435f30a6c8742da"
    );
    incremental_hash_tests!(
        sha3_256_vectors,
        Sha3_256Context,
        Sha3_256Digest,
        sha3_256,
        32,
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "9275be9357f3534948d913fc4f3a16ba763beb3ee0f9dd61482a7a0740ba197b"
    );
    incremental_hash_tests!(
        sha3_384_vectors,
        Sha3_384Context,
        Sha3_384Digest,
        sha3_384,
        48,
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
        "810bc32550268930df130c893a6003bb29099d8daa32f36ecaae7e1901e90df0bc2f52c21452aea248f88b5a1db71def"
    );
    incremental_hash_tests!(
        shake128_vectors,
        Shake128_256Context,
        Shake128_256Digest,
        shake128_256,
        32,
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
        "8bb4f9d9a8d098dda0929935b394062b0e5c44ec1782e43b64a81e41a5fb30a2"
    );
    incremental_hash_tests!(
        shake256_vectors,
        Shake256_512Context,
        Shake256_512Digest,
        shake256_512,
        64,
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
        "e3e10befc6917ae6d66f5285f92cafcce1f98f461641fe17c18ba7b9bc07cc88a77b395417ee47a897c6826804d3bc6d721761666da92d8862eb308958a81354"
    );
    incremental_hash_tests!(
        blake2s_vectors,
        Blake2s256Context,
        Blake2s256Digest,
        blake2s256,
        32,
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        "2eb9dbb0a4a7f58eac265d53d63a4d94ab109a52f14429e8b74888a42fb82293"
    );
    incremental_hash_tests!(
        blake2b_vectors,
        Blake2b512Context,
        Blake2b512Digest,
        blake2b512,
        64,
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        "848c752eabc0ac93a6cd634920e7b94150365c6b948980efcb0cc1b1a2b8f5527a77e4fe03ea389b485117f7d8d2c2ebd007f62545f8919336fe58e028f404c4"
    );

    #[test]
    fn blake3_official_vectors_and_tree_boundaries() {
        // https://github.com/BLAKE3-team/BLAKE3/blob/1.8.7/test_vectors/test_vectors.json
        // Official unkeyed hash outputs, first 32 bytes; input repeats 0..=250.
        for (length, answer) in [
            (
                0,
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            ),
            (
                1,
                "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            ),
            (
                63,
                "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
            ),
            (
                64,
                "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
            ),
            (
                65,
                "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
            ),
            (
                1023,
                "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
            ),
            (
                1024,
                "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
            ),
            (
                1025,
                "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
            ),
            (
                2048,
                "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
            ),
            (
                2049,
                "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
            ),
            (
                4096,
                "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
            ),
        ] {
            let input: Vec<u8> = (0..=250).cycle().take(length).collect();
            let expected = blake3_256(&input);
            assert_eq!(hex::encode(expected), answer);
            for size in [1, 63, 64, 65, 1023, 1024, 1025, 2048] {
                let mut context = Blake3_256Context::new();
                context.update(&[]);
                for chunk in input.chunks(size) {
                    context.update(chunk);
                }
                assert_eq!(context.fork_finish(), expected);
                assert_eq!(context.fork_finish(), expected);
                assert_eq!(context.finish(), expected);
            }
            let raw: [u8; 32] = expected.into();
            assert_eq!(Blake3_256Digest::from(raw), expected);
            assert_eq!(expected.as_array(), &raw);
            assert_eq!(
                Blake3_256Digest::try_from(raw.as_slice()).expect("exact length"),
                expected
            );
            assert!(Blake3_256Digest::try_from(&raw[..31]).is_err());
            assert!(Blake3_256Digest::try_from([0; 33].as_slice()).is_err());
        }
        let mut context = Blake3_256Context::default();
        context.update(b"a");
        assert_eq!(context.fork_finish(), blake3_256(b"a"));
        let mut fork = context.clone();
        context.update(b"bc");
        fork.update(b" different");
        assert_eq!(context.finish(), blake3_256(b"abc"));
        assert_eq!(fork.finish(), blake3_256(b"a different"));
        assert_eq!(
            format!("{:?}", Blake3_256Context::new()),
            "Blake3_256Context { .. }"
        );
    }
}
