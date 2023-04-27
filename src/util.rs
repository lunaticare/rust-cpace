use core::cmp;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use getrandom::getrandom;
use hmac_sha512::{Hash, BLOCKBYTES};

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

pub fn prepend_len_vec<T: AsRef<[u8]>>(v: &mut Vec<u8>, input: &T) -> usize {
    return prepend_len_closure(&mut |i| vec_push(v, i), input);
}

pub fn prepend_len_hash_vec<T: AsRef<[u8]>>(hash: &mut Hash, v: &mut Vec<u8>, input: &T) -> usize {
    prepend_len_hash(hash, input);
    return prepend_len_vec(v, input);
}

pub fn vec_push<T: AsRef<[u8]>>(v: &mut Vec<u8>, b: T) {
    let b_ref = b.as_ref();
    for n in 0..b_ref.len() {
        v.push(b_ref[n]);
    }
}

pub fn generator_string<T: AsRef<[u8]>>(
    dsi: &str,
    prs: &T,
    ci: &T,
    sid: &[u8],
    hash: &mut Hash,
    v: &mut Vec<u8>,
) {
    let mut prepend_len = |i: &dyn AsRef<[u8]>| prepend_len_hash_vec(hash, v, &i.as_ref());

    let mut header_len = 0;
    header_len += prepend_len(&dsi);
    header_len += prepend_len(&prs);
    let zpad = [0u8; BLOCKBYTES];
    let pad_len = cmp::max(0, zpad.len() - header_len - 1);

    prepend_len(&&zpad[..pad_len]);
    prepend_len(&ci);
    prepend_len(&sid);
}

pub fn sample_scalar() -> Result<Scalar, getrandom::Error> {
    let mut r = [0u8; 64];
    return getrandom(&mut r).map(|_| Scalar::from_bytes_mod_order_wide(&r));
}

pub fn calc_ycapital(y: &Scalar, g: &RistrettoPoint) -> RistrettoPoint {
    return g * y;
}

