use super::{
    Error,
    arithmetic::{Int, P, ZERO},
};
#[derive(Clone, Copy)]
pub(super) struct Point {
    x: Int,
    y: Int,
    z: Int,
}
impl Point {
    pub fn infinity() -> Self {
        Self {
            x: ZERO,
            y: P.one(),
            z: ZERO,
        }
    }
    pub fn generator() -> Self {
        Self {
            x: P.encode(Int([
                0xf4a13945d898c296,
                0x77037d812deb33a0,
                0xf8bce6e563a440f2,
                0x6b17d1f2e12c4247,
            ])),
            y: P.encode(Int([
                0xcbb6406837bf51f5,
                0x2bce33576b315ece,
                0x8ee7eb4a7c0f9e16,
                0x4fe342e2fe1a7f9b,
            ])),
            z: P.one(),
        }
    }
    fn select(a: Self, b: Self, bit: u64) -> Self {
        Self {
            x: Int::select(a.x, b.x, bit),
            y: Int::select(a.y, b.y, bit),
            z: Int::select(a.z, b.z, bit),
        }
    }
    pub fn double(self) -> Self {
        let delta = P.square(self.z);
        let gamma = P.square(self.y);
        let beta = P.mul(self.x, gamma);
        let alpha = P.mul(P.sub(self.x, delta), P.add(self.x, delta));
        let alpha = P.add(P.add(alpha, alpha), alpha);
        let beta2 = P.add(beta, beta);
        let beta4 = P.add(beta2, beta2);
        let beta8 = P.add(beta4, beta4);
        let x = P.sub(P.square(alpha), beta8);
        let z = P.sub(P.sub(P.square(P.add(self.y, self.z)), gamma), delta);
        let g2 = P.square(gamma);
        let g4 = P.add(g2, g2);
        let g8 = P.add(g4, g4);
        let g8 = P.add(g8, g8);
        let y = P.sub(P.mul(alpha, P.sub(beta4, x)), g8);
        Self { x, y, z }
    }
    pub fn add(self, b: Self) -> Self {
        let z1 = P.square(self.z);
        let z2 = P.square(b.z);
        let u1 = P.mul(self.x, z2);
        let u2 = P.mul(b.x, z1);
        let s1 = P.mul(self.y, P.mul(b.z, z2));
        let s2 = P.mul(b.y, P.mul(self.z, z1));
        let h = P.sub(u2, u1);
        let delta = P.sub(s2, s1);
        let h2 = P.add(h, h);
        let i = P.square(h2);
        let j = P.mul(h, i);
        let r = P.add(delta, delta);
        let v = P.mul(u1, i);
        let x = P.sub(P.sub(P.square(r), j), P.add(v, v));
        let y = P.sub(P.mul(r, P.sub(v, x)), P.add(P.mul(s1, j), P.mul(s1, j)));
        let z = P.mul(P.sub(P.sub(P.square(P.add(self.z, b.z)), z1), z2), h);
        let out = Self { x, y, z };
        let out = Self::select(out, self.double(), h.zero() & delta.zero());
        let out = Self::select(out, b, self.z.zero());
        Self::select(out, self, b.z.zero())
    }
    pub fn mul(self, scalar: Int) -> Self {
        let mut out = Self::infinity();
        for i in (0..256).rev() {
            let doubled = out.double();
            let added = doubled.add(self);
            out = Self::select(doubled, added, scalar.bit(i));
        }
        out
    }
    pub fn affine(self) -> Result<(Int, Int), Error> {
        if self.z.zero() == 1 {
            return Err(Error::InvalidPoint);
        }
        let inverse = P.inverse(self.z);
        let square = P.square(inverse);
        Ok((
            P.decode(P.mul(self.x, square)),
            P.decode(P.mul(self.y, P.mul(square, inverse))),
        ))
    }
    pub fn encode(self) -> Result<[u8; 65], Error> {
        let (x, y) = self.affine()?;
        let mut b = [0; 65];
        b[0] = 4;
        b[1..33].copy_from_slice(&x.to_be());
        b[33..].copy_from_slice(&y.to_be());
        Ok(b)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if !matches!(bytes.len(), 33 | 65) {
            return Err(Error::InvalidPoint);
        }
        let x = Int::from_be(bytes[1..33].try_into().unwrap());
        if !P.valid(x) {
            return Err(Error::InvalidPoint);
        }
        let x = P.encode(x);
        let b = P.encode(Int([
            0x3bce3c3e27d2604b,
            0x651d06b0cc53b0f6,
            0xb3ebbd55769886bc,
            0x5ac635d8aa3a93e7,
        ]));
        let rhs = P.add(P.sub(P.mul(P.square(x), x), P.add(P.add(x, x), x)), b);
        let y = match (bytes.len(), bytes[0]) {
            (65, 4) => {
                let y = Int::from_be(bytes[33..].try_into().unwrap());
                if !P.valid(y) {
                    return Err(Error::InvalidPoint);
                }
                P.encode(y)
            }
            (33, 2 | 3) => {
                let y = P.pow(
                    rhs,
                    Int([0, 0x40000000, 0x4000000000000000, 0x3fffffffc0000000]),
                );
                let parity = P.decode(y).bit(0);
                Int::select(y, P.sub(ZERO, y), parity ^ u64::from(bytes[0] & 1))
            }
            _ => return Err(Error::InvalidPoint),
        };
        if P.square(y) != rhs {
            return Err(Error::InvalidPoint);
        }
        Ok(Self { x, y, z: P.one() })
    }
}
