use core::cmp;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use getrandom::getrandom;
use hmac_sha512::{Hash, BLOCKBYTES};
use smallvec::SmallVec;

use crate::Error;

pub type SmallVec128 = SmallVec<[u8; 8]>;

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

pub fn prepend_len_smallvec<T: AsRef<[u8]>>(v: &mut SmallVec128, input: &T) -> usize {
    return prepend_len_closure(&mut |i| smallvec_push(v, i), input);
}

pub fn smallvec_push<T: AsRef<[u8]>>(v: &mut SmallVec128, b: T) {
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

impl PrependLen for SmallVec128 {
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

#[derive(Debug)]
pub enum ReadLeb128Error {
    CorruptData,
}

#[derive(Debug)]
pub struct ReadLeb128Result {
    pub result: SmallVec128,
    pub new_pos: usize,
}

pub fn read_leb128_element<T: AsRef<[u8]>>(
    input: &T,
    start_pos: usize,
) -> Result<ReadLeb128Result, ReadLeb128Error> {
    let mut result = SmallVec128::new();
    let input = input.as_ref();
    let mut pos = start_pos;
    // consume length
    let mut cur_len: i32 = 0;
    let mut read_len = false;
    while pos < input.len() {
        let b = input[pos];
        pos += 1;
        cur_len += b as i32;
        if b > 0x7f {
            cur_len = cur_len << 7;
        } else {
            read_len = true;
            break;
        }
    }
    if !read_len {
        return Err(ReadLeb128Error::CorruptData);
    }
    // consume data
    for i in 0..cur_len {
        if pos < input.len() {
            result.push(input[pos]);
            pos += 1;
        } else {
            return Err(ReadLeb128Error::CorruptData);
        }
    }
    Ok(ReadLeb128Result {
        result,
        new_pos: pos,
    })
}

pub fn read_leb128_buffer<T: AsRef<[u8]>>(input: &T) -> SmallVec<[SmallVec128; 8]> {
    let mut result = SmallVec::<[SmallVec128; 8]>::new();
    let input = input.as_ref();
    let mut pos = 0;
    while pos < input.len() {
        let read_result = read_leb128_element(&input, pos);
        match read_result {
            Ok(s) => {
                result.push(s.result);
                pos = s.new_pos;
            }
            Err(_) => {
                break;
            }
        }
    }
    result
}
