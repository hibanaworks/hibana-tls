//! Fixed four-limb Montgomery arithmetic for the P-256 field and scalar order.
//! Every multiplication uses fixed loop bounds; generated-code timing is unqualified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Int(pub [u64; 4]);
pub(super) const ZERO: Int = Int([0; 4]);
pub(super) const ONE: Int = Int([1, 0, 0, 0]);
pub(super) struct Modulus {
    pub value: Int,
    r2: Int,
    inv: u64,
}
pub(super) const P: Modulus = Modulus {
    value: Int([0xffffffffffffffff, 0xffffffff, 0, 0xffffffff00000001]),
    r2: Int([3, 0xfffffffbffffffff, 0xfffffffffffffffe, 0x4fffffffd]),
    inv: 1,
};
pub(super) const N: Modulus = Modulus {
    value: Int([
        0xf3b9cac2fc632551,
        0xbce6faada7179e84,
        0xffffffffffffffff,
        0xffffffff00000000,
    ]),
    r2: Int([
        0x83244c95be79eea2,
        0x4699799c49bd6fa6,
        0x2845b2392b6bec59,
        0x66e12d94f3d95620,
    ]),
    inv: 0xccd1c8aaee00bc4f,
};
impl Int {
    pub fn from_be(bytes: &[u8; 32]) -> Self {
        let mut a = [0; 4];
        for (i, v) in a.iter_mut().enumerate() {
            *v = u64::from_be_bytes(bytes[(3 - i) * 8..(4 - i) * 8].try_into().unwrap());
        }
        Self(a)
    }
    pub fn to_be(self) -> [u8; 32] {
        let mut b = [0; 32];
        for (i, v) in self.0.iter().enumerate() {
            b[(3 - i) * 8..(4 - i) * 8].copy_from_slice(&v.to_be_bytes());
        }
        b
    }
    pub fn bit(self, i: usize) -> u64 {
        (self.0[i / 64] >> (i % 64)) & 1
    }
    pub fn zero(self) -> u64 {
        let x = self.0[0] | self.0[1] | self.0[2] | self.0[3];
        ((x | x.wrapping_neg()) >> 63) ^ 1
    }
    pub fn select(a: Self, b: Self, bit: u64) -> Self {
        let mask = 0u64.wrapping_sub(bit);
        Self(core::array::from_fn(|i| (a.0[i] & !mask) | (b.0[i] & mask)))
    }
    pub fn sub_raw(self, b: Self) -> (Self, u64) {
        let mut out = [0; 4];
        let mut borrow = 0;
        for (i, v) in out.iter_mut().enumerate() {
            let (x, b1) = self.0[i].overflowing_sub(b.0[i]);
            let (x, b2) = x.overflowing_sub(borrow);
            *v = x;
            borrow = (b1 | b2) as u64;
        }
        (Self(out), borrow)
    }
}
impl Modulus {
    pub fn reduce(&self, a: Int) -> Int {
        let (d, b) = a.sub_raw(self.value);
        Int::select(d, a, b)
    }
    pub fn valid(&self, a: Int) -> bool {
        a.sub_raw(self.value).1 == 1
    }
    pub fn encode(&self, a: Int) -> Int {
        self.mul(self.reduce(a), self.r2)
    }
    pub fn decode(&self, a: Int) -> Int {
        self.mul(a, ONE)
    }
    pub fn one(&self) -> Int {
        self.encode(ONE)
    }
    pub fn add(&self, a: Int, b: Int) -> Int {
        let mut out = [0; 4];
        let mut carry = 0u128;
        for (i, v) in out.iter_mut().enumerate() {
            let x = a.0[i] as u128 + b.0[i] as u128 + carry;
            *v = x as u64;
            carry = x >> 64;
        }
        let out = Int(out);
        let (d, borrow) = out.sub_raw(self.value);
        Int::select(out, d, (carry as u64) | (borrow ^ 1))
    }
    pub fn sub(&self, a: Int, b: Int) -> Int {
        let (d, borrow) = a.sub_raw(b);
        let mask = 0u64.wrapping_sub(borrow);
        let mut out = [0; 4];
        let mut carry = 0u128;
        for (i, v) in out.iter_mut().enumerate() {
            let x = d.0[i] as u128 + (self.value.0[i] & mask) as u128 + carry;
            *v = x as u64;
            carry = x >> 64;
        }
        Int(out)
    }
    pub fn mul(&self, a: Int, b: Int) -> Int {
        let mut t = [0u64; 9];
        for i in 0..4 {
            let mut c = 0u128;
            for j in 0..4 {
                let x = a.0[i] as u128 * b.0[j] as u128 + t[i + j] as u128 + c;
                t[i + j] = x as u64;
                c = x >> 64;
            }
            t[i + 4] = c as u64;
        }
        for i in 0..4 {
            let q = t[i].wrapping_mul(self.inv);
            let mut c = 0u128;
            for j in 0..4 {
                let x = q as u128 * self.value.0[j] as u128 + t[i + j] as u128 + c;
                t[i + j] = x as u64;
                c = x >> 64;
            }
            for slot in t.iter_mut().skip(i + 4) {
                let x = *slot as u128 + c;
                *slot = x as u64;
                c = x >> 64;
            }
        }
        let out = Int([t[4], t[5], t[6], t[7]]);
        let (d, b) = out.sub_raw(self.value);
        Int::select(out, d, t[8] | (b ^ 1))
    }
    pub fn square(&self, a: Int) -> Int {
        self.mul(a, a)
    }
    pub fn pow(&self, a: Int, e: Int) -> Int {
        let mut out = self.one();
        for i in (0..256).rev() {
            out = self.square(out);
            let times = self.mul(out, a);
            out = Int::select(out, times, e.bit(i));
        }
        out
    }
    pub fn inverse(&self, a: Int) -> Int {
        self.pow(a, self.value.sub_raw(Int([2, 0, 0, 0])).0)
    }
}
