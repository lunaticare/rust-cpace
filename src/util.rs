use core::cmp;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use getrandom::getrandom;
use hmac_sha512::{Hash, BLOCKBYTES};
use smallvec::SmallVec;

use crate::Error;

pub fn prepend_len_closure<T: AsRef<[u8]>, F>(update: &mut F, input: T) -> usize
where
    F: FnMut(&[u8]) -> (),
{
    let input = input.as_ref();
    let mut length = input.len();
    let mut len = length;
    loop {
        if length < 128 {
            update(&[length as u8]);
        } else {
            update(&[((length & 0x7f) + 0x80) as u8]);
        }
        len += 1;
        length = length >> 7;
        if length == 0 {
            break;
        }
    }
    update(input);
    return len;
}

pub fn prepend_len_hash<T: AsRef<[u8]>>(hash: &mut Hash, input: &T) -> usize {
    return prepend_len_closure(&mut |i| hash.update(i), input);
}

pub fn prepend_len_smallvec<T: AsRef<[u8]>>(v: &mut SmallVec<[u8; 8]>, input: &T) -> usize {
    return prepend_len_closure(&mut |i| smallvec_push(v, i), input);
}

pub fn smallvec_push<T: AsRef<[u8]>>(v: &mut SmallVec<[u8; 8]>, b: T) {
    let b_ref = b.as_ref();
    for n in 0..b_ref.len() {
        v.push(b_ref[n]);
    }
}

pub trait PrependLen {
    fn prepend_len<T: AsRef<[u8]>>(&mut self, input: &T) -> usize;
}

impl PrependLen for Hash {
    fn prepend_len<T: AsRef<[u8]>>(&mut self, input: &T) -> usize {
        prepend_len_hash(self, input)
    }
}

impl PrependLen for SmallVec<[u8; 8]> {
    fn prepend_len<T: AsRef<[u8]>>(&mut self, input: &T) -> usize {
        prepend_len_smallvec(self, input)
    }
}

pub trait GetHash {
    fn get_hash(&mut self) -> [u8; 64];
}

impl GetHash for Hash {
    fn get_hash(&mut self) -> [u8; 64] {
        self.finalize()
    }
}

pub fn generator_string<T: AsRef<[u8]>, D>(dsi: &str, prs: &T, ci: &T, sid: &[u8], acc: &mut D)
where
    D: PrependLen,
{
    let mut header_len = 0;
    header_len += acc.prepend_len(&dsi);
    header_len += acc.prepend_len(&prs);
    let zpad = [0u8; BLOCKBYTES];
    let pad_len = cmp::max(0, zpad.len() - header_len - 1);

    acc.prepend_len(&&zpad[..pad_len]);
    acc.prepend_len(&ci);
    acc.prepend_len(&sid);
}

pub fn sample_scalar() -> Result<Scalar, getrandom::Error> {
    let mut r = [0u8; 64];
    return getrandom(&mut r).map(|_| Scalar::from_bytes_mod_order_wide(&r));
}

pub fn calc_ycapital(y: &Scalar, g: &RistrettoPoint) -> RistrettoPoint {
    return g * y;
}

pub fn msg<T: AsRef<[u8]>>(y: &RistrettoPoint, ad: &T) -> SmallVec<[u8; 8]> {
    let mut r = SmallVec::<[u8; 8]>::new();
    prepend_len_smallvec(&mut r, y.compress().as_bytes());
    prepend_len_smallvec(&mut r, ad);
    return r;
}

pub fn channel_identifier<T: AsRef<[u8]>>(id_a: &T, id_b: &T) -> SmallVec<[u8; 8]> {
    let mut ci = SmallVec::<[u8; 8]>::new();

    ci.prepend_len(id_a);
    ci.prepend_len(id_b);
    ci
}

pub fn scalar_mult_vfy(y: &Scalar, g: &RistrettoPoint) -> Result<RistrettoPoint, crate::Error> {
    let r = g * y;
    let is_valid = true; // TODO add verification
    if is_valid {
        return Ok(r);
    } else {
        return Err(Error::InvalidPublicKey);
    }
}
