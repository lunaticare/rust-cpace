use std::iter::FromIterator;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use hmac_sha512::Hash;
use pake_cpace::util::{
    calc_ycapital, msg, prepend_len_hash, prepend_len_vec, scalar_mult_vfy, AccumulatorOps,
};

pub const AD_A: &str = "ADa";
pub const AD_B: &str = "ADb";

pub fn g() -> RistrettoPoint {
    ristretto_point_from_compressed_encoding_hex_string(
        "5e25411ca1ad7c9debfd0b33ad987a95cefef2d3f15dcc8bd26415a5dfe2e15a",
    )
}

pub fn y_a() -> Scalar {
    scalar_from_bytes_mod_order_wide_hex_string(&String::from_iter([
        "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4f",
        "f0976d08",
    ]))
}

pub fn y_b() -> Scalar {
    scalar_from_bytes_mod_order_wide_hex_string(&String::from_iter([
        "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762",
        "d900b80d",
    ]))
}

pub fn ycapital_a() -> RistrettoPoint {
    ristretto_point_from_compressed_encoding_hex_string(&String::from_iter([
        "383a85dd236978f17f8c8545b50dabc52a39fcdab2cf8bc531ce040f",
        "f77ca82d",
    ]))
}

pub fn ycapital_b() -> RistrettoPoint {
    ristretto_point_from_compressed_encoding_hex_string(&String::from_iter([
        "a6206309c0e8e5f579295e35997ac4300ab3fecec3c17f7b604f3e69",
        "8fa1383c",
    ]))
}

pub fn k() -> RistrettoPoint {
    return ristretto_point_from_compressed_encoding_hex_string(&String::from_iter([
        "fa1d0318864e2cacb26875f1b791c9ae83204fe8359addb53e95a2e9",
        "8893853f",
    ]));
}

fn ristretto_point_from_uniform_bytes_hex_string(s: &str) -> RistrettoPoint {
    let input = hex::decode(s).expect("fail");
    let mut fixed_size_input = [0u8; 64];
    fixed_size_input.copy_from_slice(&input);
    return RistrettoPoint::from_uniform_bytes(&fixed_size_input);
}

fn ristretto_point_from_compressed_encoding_hex_string(s: &str) -> RistrettoPoint {
    let input = hex::decode(s).expect("fail");
    return CompressedRistretto::from_slice(input.as_slice())
        .decompress()
        .expect("fail");
}

fn scalar_from_bytes_mod_order_wide_hex_string(s: &str) -> Scalar {
    let input = hex::decode(s).expect("fail");
    let mut fixed_size_input = [0u8; 32];
    fixed_size_input.copy_from_slice(&input);
    return Scalar::from_bits(fixed_size_input);
}

pub struct DebugAcc {
    pub v: Vec<u8>,
    pub hash: Hash,
}

impl AccumulatorOps for DebugAcc {
    fn prepend_len<T: AsRef<[u8]>>(&mut self, input: &T) -> usize {
        prepend_len_hash(&mut self.hash, input);
        prepend_len_vec(&mut self.v, input)
    }
    fn get_hash(&mut self) -> [u8; 64] {
        self.hash.finalize()
    }
}

impl Default for DebugAcc {
    fn default() -> Self {
        DebugAcc {
            v: Vec::new(),
            hash: Hash::new(),
        }
    }
}

#[test]
fn test_prepend_len_1() {
    let mut v = Vec::<u8>::new();
    prepend_len_vec(&mut v, &"1234");
    assert_eq!(hex::encode(v.as_slice()), "0431323334");
}

#[test]
fn test_prepend_len_2() {
    let mut v = Vec::<u8>::new();
    let mut input = [0u8; 127];
    for i in 0..input.len() {
        input[i] = i as u8;
    }
    prepend_len_vec(&mut v, &input);
    assert_eq!(
        hex::encode(v.as_slice()),
        String::from_iter([
            "7f000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
            "1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738",
            "393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455",
            "565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172",
            "737475767778797a7b7c7d7e",
        ])
    );
}

#[test]
fn test_prepend_len_3() {
    let mut v = Vec::<u8>::new();
    let mut input = [0u8; 128];
    for i in 0..input.len() {
        input[i] = i as u8;
    }
    prepend_len_vec(&mut v, &input);
    assert_eq!(
        hex::encode(v.as_slice()),
        String::from_iter([
            "8001000102030405060708090a0b0c0d0e0f101112131415161718191a",
            "1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "38393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051525354",
            "55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071",
            "72737475767778797a7b7c7d7e7f",
        ])
    );
}

#[test]
fn test_calc_ycapital_1() {
    let r_actual = calc_ycapital(&y_a(), &g());
    assert_eq!(ycapital_a(), r_actual);
}

#[test]
fn test_calc_ycapital_2() {
    let r_actual = calc_ycapital(&y_b(), &g());
    let r_expected = ycapital_b();
    assert_eq!(r_expected, r_actual);
}

#[test]
fn test_msg_1() {
    let msg_a_actual = hex::encode(msg(&ycapital_a(), &AD_A));
    let msg_a_expected = String::from_iter([
        "20383a85dd236978f17f8c8545b50dabc52a39fcdab2cf8bc531ce04",
        "0ff77ca82d03414461",
    ]);
    assert_eq!(msg_a_expected, msg_a_actual);
}

#[test]
fn test_msg_2() {
    let msg_b_actual = hex::encode(msg(&ycapital_b(), &AD_B));
    let msg_b_expected = String::from_iter([
        "20a6206309c0e8e5f579295e35997ac4300ab3fecec3c17f7b604f3e",
        "698fa1383c03414462",
    ]);
    assert_eq!(msg_b_expected, msg_b_actual);
}

#[test]
fn test_scalar_mult_vfy_1() {
    assert_eq!(scalar_mult_vfy(&y_a(), &ycapital_b()).expect("fail"), k());
}

#[test]
fn test_scalar_mult_vfy_2() {
    assert_eq!(scalar_mult_vfy(&y_b(), &ycapital_a()).expect("fail"), k());
}
