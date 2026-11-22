//! Point validation of `EC` and `OKP` keys (the former follow-up gate of
//! the module docs of [`crate::jwk`]), with hand-written arithmetic and no
//! new dependency.
//!
//! - `EC` (P-256, P-384, P-521): each coordinate is below the field prime
//!   `p`, and `y^2 = x^3 - 3x + b (mod p)`. The three curves have cofactor
//!   1, so a point on the curve is in the prime-order group: with the range
//!   check this is the partial public-key validation of NIST SP 800-56A
//!   section 5.6.2.3 (the umbrella section; the subsection numbering
//!   varies by revision), which for cofactor 1 amounts to the full one
//!   (the point at infinity has no affine JWK form).
//! - `OKP` Ed25519: the RFC 8032 section 5.1.3 decoding (from memory,
//!   unverified), which refuses `y >= p = 2^255 - 19`, a `y` that does not
//!   decode to a point, and `x = 0` with the sign bit set, plus the
//!   refusal of the eight small-order points (provisional lead pick,
//!   2026-11-21). A point with a torsion component (a
//!   prime-order point plus a small-order point) is accepted: it is not
//!   claimed safe, and cofactor handling belongs to the verifier (T11.7,
//!   strict verification). This is not a full strict-verification
//!   validation.
//!
//! The arithmetic is a fixed-width unsigned integer of [`LIMBS`] 64-bit
//! limbs (576 bits: 521 bits plus headroom) with shift-and-add modular
//! multiplication, square-and-multiply exponentiation and Fermat inversion
//! (every modulus here is prime). It processes public keys only, so it is
//! not constant-time and need not be. Speed is not a goal either: an EC key
//! costs three modular multiplications, an Ed25519 key about a thousand
//! (an inversion and Euler's criterion), each a few hundred additions.

use std::cmp::Ordering;

use super::key::{EcCurve, JwkError};

/// The limbs of [`Uint`]: 576 bits.
const LIMBS: usize = 9;

/// An unsigned integer of [`LIMBS`] little-endian 64-bit limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Uint([u64; LIMBS]);

impl Uint {
    const ZERO: Self = Self([0; LIMBS]);
    const ONE: Self = Self::from_u64(1);

    const fn from_u64(value: u64) -> Self {
        let mut limbs = [0; LIMBS];
        limbs[0] = value;
        Self(limbs)
    }

    /// The value of big-endian lowercase hexadecimal `hex`. Used for the
    /// constants below, so a malformed literal is a build error.
    const fn from_hex(hex: &str) -> Self {
        let digits = hex.as_bytes();
        assert!(digits.len() <= LIMBS * 16, "hex literal over 576 bits");
        let mut limbs = [0; LIMBS];
        let mut i = 0;
        while i < digits.len() {
            let digit = digits[digits.len() - 1 - i];
            let value = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                _ => panic!("not a lowercase hex digit"),
            };
            limbs[i / 16] |= (value as u64) << (4 * (i % 16));
            i += 1;
        }
        Self(limbs)
    }

    /// The value of big-endian `bytes`, or `None` when it has more octets
    /// than fit.
    fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > LIMBS * 8 {
            return None;
        }
        let mut limbs = [0; LIMBS];
        for (i, &byte) in bytes.iter().rev().enumerate() {
            limbs[i / 8] |= u64::from(byte) << (8 * (i % 8));
        }
        Some(Self(limbs))
    }

    /// `self + other` modulo 2^576, and the carry out.
    fn add(&self, other: &Self) -> (Self, bool) {
        let mut limbs = [0; LIMBS];
        let mut carry = false;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let (sum, first) = self.0[i].overflowing_add(other.0[i]);
            let (sum, second) = sum.overflowing_add(u64::from(carry));
            *limb = sum;
            carry = first || second;
        }
        (Self(limbs), carry)
    }

    /// `self - other` modulo 2^576, and the borrow out.
    fn sub(&self, other: &Self) -> (Self, bool) {
        let mut limbs = [0; LIMBS];
        let mut borrow = false;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let (diff, first) = self.0[i].overflowing_sub(other.0[i]);
            let (diff, second) = diff.overflowing_sub(u64::from(borrow));
            *limb = diff;
            borrow = first || second;
        }
        (Self(limbs), borrow)
    }

    /// `self >> 1`.
    fn shr1(&self) -> Self {
        let mut limbs = [0; LIMBS];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let high = self.0.get(i + 1).map_or(0, |next| next << 63);
            *limb = self.0[i] >> 1 | high;
        }
        Self(limbs)
    }

    /// Bit `i`, counted from the least significant.
    fn bit(&self, i: usize) -> bool {
        self.0[i / 64] >> (i % 64) & 1 == 1
    }

    /// The number of significant bits.
    fn bits(&self) -> usize {
        match self.0.iter().rposition(|&limb| limb != 0) {
            Some(top) => top * 64 + 64 - self.0[top].leading_zeros() as usize,
            None => 0,
        }
    }
}

impl Ord for Uint {
    fn cmp(&self, other: &Self) -> Ordering {
        // Most significant limb first.
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for Uint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// `a + b mod p`, for `a, b < p`. The sum stays under `2p < 2^576`, so it
/// never carries out.
fn add_mod(a: &Uint, b: &Uint, p: &Uint) -> Uint {
    let (sum, _) = a.add(b);
    if sum >= *p { sum.sub(p).0 } else { sum }
}

/// `a - b mod p`, for `a, b < p`. On a borrow, adding `p` wraps back into
/// range (its carry out is the borrow's 2^576).
fn sub_mod(a: &Uint, b: &Uint, p: &Uint) -> Uint {
    let (diff, borrow) = a.sub(b);
    if borrow { diff.add(p).0 } else { diff }
}

/// `a * b mod p`, for `a, b < p`: shift-and-add over the bits of `b`.
fn mul_mod(a: &Uint, b: &Uint, p: &Uint) -> Uint {
    let mut product = Uint::ZERO;
    for i in (0..b.bits()).rev() {
        product = add_mod(&product, &product, p);
        if b.bit(i) {
            product = add_mod(&product, a, p);
        }
    }
    product
}

/// `base^exponent mod p`, for `base < p` and `p > 1`: square-and-multiply.
fn pow_mod(base: &Uint, exponent: &Uint, p: &Uint) -> Uint {
    let mut power = Uint::ONE;
    for i in (0..exponent.bits()).rev() {
        power = mul_mod(&power, &power, p);
        if exponent.bit(i) {
            power = mul_mod(&power, base, p);
        }
    }
    power
}

/// `1 / a mod p`, for a prime `p` and `0 < a < p`: `a^(p-2)` (Fermat).
fn inv_mod(a: &Uint, p: &Uint) -> Uint {
    pow_mod(a, &p.sub(&Uint::from_u64(2)).0, p)
}

/// The value of big-endian `bytes` when it is below `p`.
fn below(bytes: &[u8], p: &Uint) -> Option<Uint> {
    Uint::from_be_bytes(bytes).filter(|value| value < p)
}

// The curve constants. Each was checked against two sources besides its
// literal here (FIPS 186-4 appendix D.1.2 and SEC 2 version 2 for the NIST
// curves, RFC 8032 section 5.1 for Ed25519, as remembered): a Python
// recomputation (scratchpad, not this module's output), which found
// - each NIST `p` equal to its formula (P-256: 2^256 - 2^224 + 2^192 +
//   2^96 - 1; P-384: 2^384 - 2^128 - 2^96 + 2^32 - 1; P-521: 2^521 - 1),
//   which the unit tests below repeat;
// - each NIST `b` satisfying the curve equation at OpenSSL's generator
//   (Python `cryptography`, private key 1) and at 20 keys `cryptography`
//   generated, and `b^2 * c = -27 (mod p)` for the `c` derived from the
//   curve's published SEED (FIPS 186-4 appendix A.1.1.1, ANSI X9.62);
// - Ed25519's `p = 2^255 - 19` and `d = -121665/121666 mod p`, equal to
//   RFC 8032's decimal `d` 3709570593466943934313808350875456518954211387
//   9843219016388785533085940283555 (the unit tests recompute both), and
//   20 Ed25519 keys `cryptography` generated decoding with that `d`.

/// P-256 `p` (FIPS 186-4 D.1.2.3).
const P256_P: Uint =
    Uint::from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
/// P-256 `b` (FIPS 186-4 D.1.2.3).
const P256_B: Uint =
    Uint::from_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
/// P-384 `p` (FIPS 186-4 D.1.2.4).
const P384_P: Uint = Uint::from_hex(concat!(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    "ffffffff0000000000000000ffffffff",
));
/// P-384 `b` (FIPS 186-4 D.1.2.4).
const P384_B: Uint = Uint::from_hex(concat!(
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a",
    "c656398d8a2ed19d2a85c8edd3ec2aef",
));
/// P-521 `p` (FIPS 186-4 D.1.2.5).
const P521_P: Uint = Uint::from_hex(concat!(
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "ffff",
));
/// P-521 `b` (FIPS 186-4 D.1.2.5).
const P521_B: Uint = Uint::from_hex(concat!(
    "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1",
    "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50",
    "3f00",
));
/// Ed25519 `p = 2^255 - 19` (RFC 8032 section 5.1).
const ED25519_P: Uint =
    Uint::from_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
/// Ed25519 `d = -121665/121666 mod p` (RFC 8032 section 5.1).
const ED25519_D: Uint =
    Uint::from_hex("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
/// The `y` of two of the four Ed25519 points of order 8; `p - y` is the
/// `y` of the other two. With `y` = 0 (order 4), 1 (the identity) and
/// `p - 1` (order 2) these are the `y`s of all eight points of order
/// dividing 8, found independently in Python (multiplying random points by
/// the group order `L` until eight distinct points appeared, each with
/// `8P` the identity).
const ED25519_Y8: Uint =
    Uint::from_hex("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7");

/// Checks that `(x, y)`, big-endian coordinates of the curve's length, is
/// a point of `curve`.
pub(super) fn check_ec(curve: EcCurve, x: &[u8], y: &[u8]) -> Result<(), JwkError> {
    let (p, b) = match curve {
        EcCurve::P256 => (P256_P, P256_B),
        EcCurve::P384 => (P384_P, P384_B),
        EcCurve::P521 => (P521_P, P521_B),
    };
    let x = below(x, &p).ok_or(JwkError::CoordinateOutOfRange { member: "x" })?;
    let y = below(y, &p).ok_or(JwkError::CoordinateOutOfRange { member: "y" })?;
    // x^3 - 3x + b
    let cube = mul_mod(&mul_mod(&x, &x, &p), &x, &p);
    let three_x = add_mod(&add_mod(&x, &x, &p), &x, &p);
    let rhs = add_mod(&sub_mod(&cube, &three_x, &p), &b, &p);
    if mul_mod(&y, &y, &p) != rhs {
        return Err(JwkError::PointNotOnCurve);
    }
    Ok(())
}

/// Checks that `encoded`, a 32-octet Ed25519 public key, is a canonical
/// encoding of a point outside the small-order subgroup (see the module
/// docs: a torsion component is not refused).
pub(super) fn check_ed25519(encoded: &[u8]) -> Result<(), JwkError> {
    let p = ED25519_P;
    // RFC 8032 section 5.1.3: little-endian `y` in the low 255 bits, the
    // sign of `x` in the top bit.
    let sign = encoded.last().is_some_and(|last| last & 0x80 != 0);
    let mut big_endian: Vec<u8> = encoded.iter().rev().copied().collect();
    if let Some(top) = big_endian.first_mut() {
        *top &= 0x7f;
    }
    let y = below(&big_endian, &p).ok_or(JwkError::Ed25519NotCanonical)?;
    // x^2 = (y^2 - 1) / (d y^2 + 1); the denominator is never 0, since d
    // is not a square mod p.
    let y2 = mul_mod(&y, &y, &p);
    let u = sub_mod(&y2, &Uint::ONE, &p);
    let v = add_mod(&mul_mod(&ED25519_D, &y2, &p), &Uint::ONE, &p);
    let x2 = mul_mod(&u, &inv_mod(&v, &p), &p);
    if x2 == Uint::ZERO {
        // x = 0 has no negative: the sign bit must be clear.
        if sign {
            return Err(JwkError::Ed25519NotCanonical);
        }
    } else if pow_mod(&x2, &p.shr1(), &p) != Uint::ONE {
        // Euler's criterion, x2^((p-1)/2) = 1 for a square; p is odd, so
        // (p-1)/2 is p >> 1.
        return Err(JwkError::PointNotOnCurve);
    }
    let small_order = [
        Uint::ZERO,
        Uint::ONE,
        p.sub(&Uint::ONE).0,
        ED25519_Y8,
        p.sub(&ED25519_Y8).0,
    ];
    if small_order.contains(&y) {
        return Err(JwkError::Ed25519SmallOrder);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2^k.
    fn pow2(k: usize) -> Uint {
        let mut limbs = [0; LIMBS];
        limbs[k / 64] = 1 << (k % 64);
        Uint(limbs)
    }

    fn plus(a: Uint, b: Uint) -> Uint {
        let (sum, carry) = a.add(&b);
        assert!(!carry);
        sum
    }

    fn minus(a: Uint, b: Uint) -> Uint {
        let (diff, borrow) = a.sub(&b);
        assert!(!borrow);
        diff
    }

    #[test]
    fn primes_match_their_formulas() {
        let one = Uint::ONE;
        let p256 = minus(
            plus(plus(minus(pow2(256), pow2(224)), pow2(192)), pow2(96)),
            one,
        );
        assert_eq!(p256, P256_P);
        let p384 = minus(
            plus(minus(minus(pow2(384), pow2(128)), pow2(96)), pow2(32)),
            one,
        );
        assert_eq!(p384, P384_P);
        assert_eq!(minus(pow2(521), one), P521_P);
        assert_eq!(minus(pow2(255), Uint::from_u64(19)), ED25519_P);
    }

    #[test]
    fn ed25519_d_is_minus_121665_over_121666() {
        let p = ED25519_P;
        let minus_121665 = sub_mod(&Uint::ZERO, &Uint::from_u64(121665), &p);
        let d = mul_mod(&minus_121665, &inv_mod(&Uint::from_u64(121666), &p), &p);
        assert_eq!(d, ED25519_D);
        // RFC 8032's decimal d, 37095705934669439343138083508754565189542
        // 113879843219016388785533085940283555, built from 18-digit parts.
        let parts = [
            37_095_705_934_669u64,
            439_343_138_083_508_754,
            565_189_542_113_879_843,
            219_016_388_785_533_085,
            940_283_555,
        ];
        let widths = [0u32, 18, 18, 18, 9];
        let mut decimal = Uint::ZERO;
        let modulus = P521_P; // larger than d: no reduction happens
        for (part, width) in parts.into_iter().zip(widths) {
            let scale = Uint::from_u64(10u64.pow(width));
            decimal = add_mod(
                &mul_mod(&decimal, &scale, &modulus),
                &Uint::from_u64(part),
                &modulus,
            );
        }
        assert_eq!(decimal, ED25519_D);
    }

    #[test]
    fn from_hex_and_from_be_bytes_agree() {
        assert_eq!(Uint::from_hex("0"), Uint::ZERO);
        assert_eq!(
            Uint::from_hex("0102030405060708090a"),
            Uint::from_be_bytes(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).unwrap()
        );
        assert_eq!(
            Uint::from_hex("0102030405060708090a").0[..2],
            [0x0304_0506_0708_090a, 0x0102]
        );
        assert_eq!(Uint::from_be_bytes(&[]), Some(Uint::ZERO));
        assert_eq!(
            Uint::from_be_bytes(&[0xff; 72]),
            Some(Uint([u64::MAX; LIMBS]))
        );
        assert_eq!(Uint::from_be_bytes(&[0; 73]), None);
    }

    #[test]
    fn add_and_sub_carry_across_limbs() {
        let max = Uint([u64::MAX; LIMBS]);
        assert_eq!(max.add(&Uint::ONE), (Uint::ZERO, true));
        assert_eq!(Uint::ZERO.sub(&Uint::ONE), (max, true));
        assert_eq!(Uint::from_u64(u64::MAX).add(&Uint::ONE), (pow2(64), false));
        assert_eq!(pow2(64).sub(&Uint::ONE), (Uint::from_u64(u64::MAX), false));
        assert_eq!(pow2(575).add(&pow2(575)), (Uint::ZERO, true));
        assert_eq!(pow2(300).sub(&pow2(300)), (Uint::ZERO, false));
    }

    #[test]
    fn shifts_bits_and_order() {
        assert_eq!(pow2(64).shr1(), pow2(63));
        assert_eq!(pow2(575).shr1(), pow2(574));
        assert_eq!(Uint::ONE.shr1(), Uint::ZERO);
        assert_eq!(Uint::ZERO.bits(), 0);
        assert_eq!(Uint::ONE.bits(), 1);
        assert_eq!(pow2(64).bits(), 65);
        assert_eq!(P521_P.bits(), 521);
        assert!(pow2(130).bit(130));
        assert!(!pow2(130).bit(129));
        assert!(pow2(64) > Uint::from_u64(u64::MAX));
        assert!(Uint::from_u64(2) > Uint::ONE);
        assert!(pow2(575) > P521_P);
        assert_eq!(P256_P.cmp(&P256_P), Ordering::Equal);
    }

    /// Known answers computed with Python integers (`a`, `b`, `e` from
    /// SHA-512 of fixed tags, reduced mod `p`).
    struct Kat {
        p: Uint,
        a: &'static str,
        b: &'static str,
        e: &'static str,
        product: &'static str,
        sum: &'static str,
        a_minus_b: &'static str,
        b_minus_a: &'static str,
        power: &'static str,
        inverse: &'static str,
    }

    const KATS: [Kat; 3] = [
        Kat {
            p: P256_P,
            a: "2411b3ed91233997906578f5ae1012fc5f7d4012df936081df0c4b3d2f9276ff",
            b: "6c628f16037a9e771fc47344b520087747c29d07693de41d93b5c756502c3241",
            e: "b51a78fb08e6d4c506ed02c61163d63b3fbd898007fc11b027f70d3e0f729f48",
            product: "eda686931505509a146e83f7bc2ed43cc04b6d4d3e36d24712148eaa808ec288",
            sum: "90744303949dd80eb029ec3a63301b73a73fdd1a48d1449f72c212937fbea940",
            a_minus_b: "b7af24d68da89b2170a105b0f8f00a8517baa30c76557c644b5683e6df6644bd",
            b_minus_a: "4850db28725764df8f5efa4f070ff57ae8455cf489aa839bb4a97c192099bb42",
            power: "b87447dbce7745a52cc3e1e4eaf120de754007ceab1cee6415918eab9506eacf",
            inverse: "3e1642f253c5e4f7e155885e3082def754bf9ae78b84c618b16578d0cb920748",
        },
        Kat {
            p: P521_P,
            a: "b3ff6698c98498672c2460e0e0a3fdba86905da891cd84091fc1a332d9a21bd1d6d701c99ffcd57307bffdb8efa28ece47ecca4e7fba4f6e6ec9f7d0b66e03f78a",
            b: "19e18cc54bc1feed2574600543ec6431e2fa4d6be10b71f9d40288bdaddf4fda67e2ae780ba5cdb261d9a1a5151482e733286c3476b853ee0c710a036f376ae610f",
            e: "1796118458d6065c0b20bdbf7d317d40c1ddaaa42620a2025e77bb08833fcad9042688626c6e3dd2f2906a53095db12e156483fbf875ac588d5b04e8bf51cfd6222",
            product: "1b657418f69fd10da85b3c470e816f481699ac0c9a9bc4ee41011ddf86c070c719f891f2bd474cf85dae79ab55b7dbea64caa1a11280bb146ce9ab191be1e013abf",
            sum: "521832ed85a48739836a61351f6a40d8b6353466a284a3a65fea2f0db79719785501e94a5a59b099255a180a40eabd417a738d95eb3f8e4f35da9807a9e4b2589a",
            a_minus_b: "115e69a440d64a994d4de608ca1ddba9c56eb86ea8116646bdf991757fbad1e2b58ac1a48e59ffa4cea25e3679e5a605b156607071435108da7b95799c2f755967a",
            b_minus_a: "ea1965bbf29b566b2b219f735e224563a91479157ee99b942066e8a80452e1d4a753e5b71a6005b315da1c9861a59fa4ea99f8f8ebcaef725846a8663d08aa6985",
            power: "1cf55971a3f87601e401c8e781aab0bdbe4831b034cfbf8304e145ff24cc87b8a857e7aceaaa4ace11299aadf6157fc4896b0bd921dbdf10a77ef58238112ee0645",
            inverse: "9177fa46d0bb24409544867a865914c823214871ab07be5df5476372ccffdc41dfcc58b8a20be69044b2caa75328081b6994fc9405e353c3283564058a003b68a7",
        },
        Kat {
            p: ED25519_P,
            a: "67d6dfeb597750eb875e4e917cec4babbdaeec2c6f3b62bafa0fb953398c7aa",
            b: "6d8cdae6af819672fdb2c406d0282f52f1fed5df2389ce7042abaab880d2719a",
            e: "36d31ded1c08197e967e257d338dd2ddb362ab0389be23bb38135c8235b51f79",
            product: "68f32fbb85c8566b1fa30c9391db57945587d05adfd4f6e94e7f1aaa0146b3c2",
            sum: "740a48e565190b81b628a8efe7f6f40dadd9c4a1ea7d849bf24ca64db46b3944",
            a_minus_b: "18f093180615de9bbac320e247a69567c9dc18e3a369e7bb6cf550dcb2c655fd",
            b_minus_a: "670f6ce7f9ea2164453cdf1db8596a983623e71c5c961844930aaf234d39a9f0",
            power: "442b6c36e689629ecb787e0eae67e034a85f9df0ad86107303c4f2eab9e936a5",
            inverse: "1b8f8d526f38be7815c92e5c557c750a776175559ff35022cc6953c76c21a69d",
        },
    ];

    #[test]
    fn modular_arithmetic_known_answers() {
        for kat in &KATS {
            let p = &kat.p;
            let hex = Uint::from_hex;
            let (a, b, e) = (hex(kat.a), hex(kat.b), hex(kat.e));
            assert_eq!(mul_mod(&a, &b, p), hex(kat.product));
            assert_eq!(mul_mod(&b, &a, p), hex(kat.product));
            assert_eq!(add_mod(&a, &b, p), hex(kat.sum));
            assert_eq!(sub_mod(&a, &b, p), hex(kat.a_minus_b));
            assert_eq!(sub_mod(&b, &a, p), hex(kat.b_minus_a));
            assert_eq!(pow_mod(&a, &e, p), hex(kat.power));
            assert_eq!(inv_mod(&a, p), hex(kat.inverse));
            assert_eq!(mul_mod(&a, &inv_mod(&a, p), p), Uint::ONE);
            assert_eq!(pow_mod(&a, &Uint::ZERO, p), Uint::ONE);
            assert_eq!(mul_mod(&a, &Uint::ZERO, p), Uint::ZERO);
        }
    }

    #[test]
    fn modular_edges() {
        let p = &P256_P;
        let p_minus_1 = minus(P256_P, Uint::ONE);
        // (p - 1)^2 = 1, (p - 1) + 1 = 0, 0 - 1 = p - 1.
        assert_eq!(mul_mod(&p_minus_1, &p_minus_1, p), Uint::ONE);
        assert_eq!(add_mod(&p_minus_1, &Uint::ONE, p), Uint::ZERO);
        assert_eq!(
            add_mod(&p_minus_1, &p_minus_1, p),
            minus(p_minus_1, Uint::ONE)
        );
        assert_eq!(sub_mod(&Uint::ZERO, &Uint::ONE, p), p_minus_1);
        assert_eq!(sub_mod(&Uint::ONE, &Uint::ONE, p), Uint::ZERO);
    }
}
