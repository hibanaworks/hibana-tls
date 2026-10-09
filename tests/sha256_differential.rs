use hibana_tls::crypto::sha256::Sha256;
#[test]
fn independent_hashlib_boundary_corpus() {
    let corpus = include_bytes!("vectors/sha256-hashlib.bin");
    assert_eq!(corpus.len(), 810 * 37);
    let mut bytes = [0u8; 4097];
    for row in corpus.chunks_exact(37) {
        let n = u32::from_be_bytes(row[..4].try_into().unwrap()) as usize;
        let seed = usize::from(row[4]);
        for (i, byte) in bytes[..n].iter_mut().enumerate() {
            *byte = ((i * 73 + seed) ^ (i >> 3)) as u8;
        }
        let expected = &row[5..];
        assert_eq!(Sha256::digest(&bytes[..n]).unwrap(), expected);
        for size in [1, 7, 31, 55, 56, 63, 64, 65, 127, 193] {
            let mut hash = Sha256::new();
            for chunk in bytes[..n].chunks(size) {
                hash.update(chunk).unwrap();
                hash.update(&[]).unwrap();
            }
            assert_eq!(hash.finish(), expected, "length {n}, chunk {size}");
        }
    }
}
