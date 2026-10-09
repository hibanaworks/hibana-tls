//! Fixed-storage, one-use X25519 secret ownership over hibana-tls arithmetic.
//! Each owner consumes a fresh injected
//! secret exactly once and rejects non-contributory (all-zero) shared secrets.
use crate::crypto::x25519;
use crate::entropy::Entropy;
#[cfg(test)]
use crate::entropy::Unavailable;
use crate::secret::Secret;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Entropy,
    InvalidShare,
    NonContributory,
}

/// The secret moves into `complete`; it cannot be reused or copied.
/// ```compile_fail
/// use hibana_tls::key_exchange::X25519Secret;
/// fn reuse(secret: X25519Secret, peer: &[u8]) {
///     let _ = secret.complete(peer);
///     let _ = secret.complete(peer);
/// }
/// ```
pub struct X25519Secret(Secret<[u8; 32]>);
impl X25519Secret {
    pub fn generate<R: Entropy>(rng: &mut R) -> Result<Self, Error> {
        let mut bytes = Secret::new([0; 32]);
        rng.try_fill_bytes(&mut *bytes)
            .map_err(|_| Error::Entropy)?;
        Ok(Self(bytes))
    }
    pub fn public_key(&self) -> [u8; 32] {
        let mut base = [0; 32];
        base[0] = 9;
        x25519::exchange(&self.0, &base)
    }
    pub fn complete(self, peer: &[u8]) -> Result<Secret<[u8; 32]>, Error> {
        let bytes: [u8; 32] = peer.try_into().map_err(|_| Error::InvalidShare)?;
        let shared = Secret::new(x25519::exchange(&self.0, &bytes));
        if bool::from(crate::secret::FixedTimeEq::fixed_time_eq(
            &*shared, &[0u8; 32],
        )) {
            return Err(Error::NonContributory);
        }
        Ok(shared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
    fn secret(s: &str) -> X25519Secret {
        X25519Secret(Secret::new(hex(s)))
    }
    #[test]
    fn rfc7748_section_61_agreement() {
        let a = secret("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = secret("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let ap = a.public_key();
        let bp = b.public_key();
        assert_eq!(
            ap,
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bp,
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(*a.complete(&bp).unwrap(), expected);
        assert_eq!(*b.complete(&ap).unwrap(), expected);
    }
    #[test]
    fn invalid_lengths_and_low_order_points_reject() {
        for len in [0, 1, 31, 33, 65] {
            assert_eq!(
                X25519Secret(Secret::new([7; 32]))
                    .complete(&[0; 65][..len])
                    .unwrap_err(),
                Error::InvalidShare
            );
        }
        for first in [0, 1] {
            let mut p = [0; 32];
            p[0] = first;
            assert_eq!(
                X25519Secret(Secret::new([7; 32])).complete(&p).unwrap_err(),
                Error::NonContributory
            );
        }
    }
    #[test]
    fn rfc7748_masks_public_high_bit() {
        let a = Secret::new([9; 32]);
        let mut p = X25519Secret(Secret::new([11; 32])).public_key();
        let first = X25519Secret(a).complete(&p).unwrap();
        p[31] |= 128;
        assert_eq!(
            *first,
            *X25519Secret(Secret::new([9; 32])).complete(&p).unwrap()
        );
    }
    struct Entropy {
        next: u8,
        fail: bool,
    }
    impl crate::entropy::Entropy for Entropy {
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Unavailable> {
            if self.fail {
                return Err(Unavailable);
            }
            for b in dest {
                *b = self.next;
                self.next = self.next.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn fresh_injected_entropy_and_failure_are_explicit() {
        let mut rng = Entropy {
            next: 1,
            fail: false,
        };
        let a = X25519Secret::generate(&mut rng).unwrap();
        let b = X25519Secret::generate(&mut rng).unwrap();
        assert_ne!(a.public_key(), b.public_key());
        rng.fail = true;
        assert!(matches!(
            X25519Secret::generate(&mut rng),
            Err(Error::Entropy)
        ));
    }
}
