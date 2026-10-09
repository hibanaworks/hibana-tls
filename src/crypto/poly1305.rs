//! Poly1305 one-time authenticator (RFC 8439 section 2.5).
//! Fixed storage, no allocator or external arithmetic library. This primitive
//! does not enforce one-time key ownership and is not an AEAD implementation.
//! Target-level timing and secret-erasure qualification remain outstanding.
const MASK: u64 = (1 << 26) - 1;

fn limbs(bytes: &[u8; 17]) -> [u64; 5] {
    let mut out = [0; 5];
    for bit in 0..130 {
        out[bit / 26] |= u64::from((bytes[bit / 8] >> (bit % 8)) & 1) << (bit % 26);
    }
    out
}

fn reduce(mut value: [u64; 5]) -> [u64; 5] {
    // 2^130 = 5 mod p. Products entering here are bounded below 2^58.
    // Three fixed sweeps normalize the wrapped carry without a secret loop.
    for _ in 0..3 {
        for i in 0..4 {
            value[i + 1] += value[i] >> 26;
            value[i] &= MASK;
        }
        let carry = value[4] >> 26;
        value[4] &= MASK;
        value[0] += carry * 5;
    }
    // Canonical subtraction of p using the carry from h + 5.
    let mut candidate = value;
    let mut carry = 5;
    for limb in &mut candidate {
        let sum = *limb + carry;
        *limb = sum & MASK;
        carry = sum >> 26;
    }
    let select = 0u64.wrapping_sub(carry);
    for i in 0..5 {
        value[i] = (candidate[i] & select) | (value[i] & !select);
    }
    value
}

/// Authenticate one message with a fresh unpredictable 32-byte one-time key.
/// Reusing this key for another message is unsafe; its lifecycle must be owned
/// by the calling protocol. No implicit nonce or counter is managed here.
pub fn authenticate(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    authenticate_parts(key, &[message])
}

// Numeric block feeding only; part boundaries do not end a Poly1305 block.
pub(crate) fn authenticate_parts(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 16] {
    let mut clamped = [0; 17];
    clamped[..16].copy_from_slice(&key[..16]);
    for i in [3, 7, 11, 15] {
        clamped[i] &= 15;
    }
    for i in [4, 8, 12] {
        clamped[i] &= 252;
    }
    let r = limbs(&clamped);
    let mut h = [0u64; 5];
    let mut pending = [0; 16];
    let mut used = 0;
    for &part in parts {
        let mut rest = part;
        while !rest.is_empty() {
            let count = rest.len().min(16 - used);
            pending[used..used + count].copy_from_slice(&rest[..count]);
            used += count;
            rest = &rest[count..];
            if used == 16 {
                absorb(&mut h, &r, &pending);
                used = 0;
            }
        }
    }
    if used != 0 {
        absorb(&mut h, &r, &pending[..used]);
    }
    let mut tag = [0u8; 16];
    for bit in 0..128 {
        tag[bit / 8] |= (((h[bit / 26] >> (bit % 26)) & 1) as u8) << (bit % 8);
    }
    let mut carry = 0u16;
    for i in 0..16 {
        let sum = u16::from(tag[i]) + u16::from(key[16 + i]) + carry;
        tag[i] = sum as u8;
        carry = sum >> 8;
    }
    tag
}

fn absorb(h: &mut [u64; 5], r: &[u64; 5], chunk: &[u8]) {
    let mut encoded = [0; 17];
    encoded[..chunk.len()].copy_from_slice(chunk);
    encoded[chunk.len()] = 1;
    let block = limbs(&encoded);
    for i in 0..5 {
        h[i] += block[i];
    }
    let mut product = [0u64; 5];
    for (i, &left) in h.iter().enumerate() {
        for (j, &right) in r.iter().enumerate() {
            let degree = i + j;
            let factor = if degree >= 5 { 5 } else { 1 };
            product[degree % 5] += left * right * factor;
        }
    }
    *h = reduce(product);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex<const N: usize>(s: &str) -> [u8; N] {
        core::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
    }
    #[test]
    fn rfc8439_message_tag() {
        let key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        assert_eq!(
            authenticate(&key, b"Cryptographic Forum Research Group"),
            hex("a8061dc1305136c6c22b8baf0c0127a9")
        );
    }
    #[test]
    fn empty_and_zero_r_use_the_pad() {
        let key = core::array::from_fn(|i| i as u8);
        assert_eq!(authenticate(&key, b""), key[16..]);
        let mut key = [0; 32];
        key[16..].fill(255);
        assert_eq!(authenticate(&key, &[255; 4097]), [255; 16]);
    }
    #[test]
    fn python_integer_oracle_corpus() {
        let mut message = [0; 4097];
        for &(seed, len, expected) in include!("../../tests/poly1305_vectors.in") {
            let key = core::array::from_fn(|i| {
                if seed == 256 {
                    255
                } else {
                    (seed as u8)
                        .wrapping_mul(19)
                        .wrapping_add((i as u8).wrapping_mul(11))
                }
            });
            for (i, byte) in message[..len].iter_mut().enumerate() {
                *byte = if seed == 256 {
                    255
                } else {
                    (i as u8).wrapping_mul(37).wrapping_add(seed as u8)
                };
            }
            assert_eq!(
                authenticate(&key, &message[..len]),
                hex::<16>(expected),
                "seed={seed}, len={len}"
            );
        }
    }
    #[test]
    fn every_split_preserves_block_encoding() {
        let key = [91; 32];
        let message: [u8; 65] = core::array::from_fn(|i| i as u8);
        for len in 0..=65 {
            for split in 0..=len {
                assert_eq!(
                    authenticate_parts(&key, &[&message[..split], &[], &message[split..len]]),
                    authenticate(&key, &message[..len])
                );
            }
        }
    }
    #[test]
    fn carry_boundaries_reduce_canonically() {
        assert_eq!(reduce([MASK - 4, MASK, MASK, MASK, MASK]), [0; 5]);
        assert_eq!(reduce([MASK - 3, MASK, MASK, MASK, MASK]), [1, 0, 0, 0, 0]);
        assert_eq!(reduce([MASK, MASK, MASK, MASK, MASK]), [4, 0, 0, 0, 0]);
    }
}
