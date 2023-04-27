use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use hex;
use hmac_sha512::{Hash, BLOCKBYTES, BYTES as SHA512_BYTES};
use mockall::predicate::*;
use mockall::*;
use pake_cpace::{CPace, DSI};
use std::{iter::FromIterator, str};

mod test_util;
use test_util::{g, y_a, y_b, AD_A, AD_B};

const CI: &str = "\nAinitiator\nBresponder";
const PASSWORD: &str = "Password";
const SESSION_ID: [u8; 16] = [
    0x7e, 0x4b, 0x47, 0x91, 0xd6, 0xa8, 0xef, 0x01, 0x9b, 0x93, 0x6c, 0x79, 0xfb, 0x7f, 0x2c, 0x57,
];

#[test]
fn test_cpace() {
    let id_a = "client";
    let id_b = "server";
    let ci = format!("{}{}", id_a, id_b).as_str().to_owned();
    let client = CPace::step1("password", &ci, Some("ad")).unwrap();

    let step2 = CPace::step2(&client.packet(), "password", &ci, Some(AD_A), Some(AD_B)).unwrap();

    let shared_keys = client
        .step3(&step2.packet(), Some(AD_A), Some(AD_B))
        .unwrap();

    assert_eq!(shared_keys.k1, step2.shared_keys().k1);
    assert_eq!(shared_keys.k2, step2.shared_keys().k2);
}

#[test]
fn test_calculate_generator() {
    let result = CPace::new(SESSION_ID, PASSWORD, CI, DSI, &mut || Ok(y_a())).unwrap();
    assert_eq!(
        hex::encode(result.generator.as_slice()),
        String::from_iter([
            "11435061636552697374726574746f3235350850617373776f726464",
            "00000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000160a41696e69746961746f72",
            "0a42726573706f6e646572107e4b4791d6a8ef019b936c79fb7f2c57",
        ])
    );
    assert_eq!(
        hex::encode(&result.h),
        String::from_iter([
            "a5ce446f63a1ae6d1fee80fa67d0b4004a4b1283ec5549a462bf33a6",
            "c1ae06a0871f9bf48545f49b2a792eed255ac04f52758c9c60448306",
            "810b44e986e3dcbb",
        ])
    );

    assert_eq!(RistrettoPoint::from_uniform_bytes(&result.h), g(),);
}

// https://github.com/cfrg/draft-irtf-cfrg-voprf/blob/3a651b9f148953ddedbd2a120f6c0b092b41c0d9/poc/ristretto_decaf.sage#L387-L400
#[test]
fn test_ietf_voprf_spec_1() {
    let input = hex::decode("5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6").unwrap();
    let mut fixed_size_input = [0u8; 64];
    fixed_size_input.copy_from_slice(&input);
    let p1 = RistrettoPoint::from_uniform_bytes(&fixed_size_input);
    let p2 = CompressedRistretto::from_slice(
        hex::decode("3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46")
            .unwrap()
            .as_slice(),
    )
    .decompress()
    .unwrap();
    assert_eq!(p1, p2);
}

#[test]
fn test_ietf_voprf_spec_2() {
    let input = hex::decode("165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413").unwrap();
    let mut fixed_size_input = [0u8; 64];
    fixed_size_input.copy_from_slice(&input);
    let p1 = RistrettoPoint::from_uniform_bytes(&fixed_size_input);
    let p2 = CompressedRistretto::from_slice(
        hex::decode("ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179")
            .unwrap()
            .as_slice(),
    )
    .decompress()
    .unwrap();
    assert_eq!(p1, p2);
}

#[test]
fn test_decode_compressed_ristretto_point_from_test_case() {
    let encoded_generator_g = "9c5712178570957204d89ac11acbef789dd076992ba361429acb2bc38c71d14c";
    let x = hex::decode(encoded_generator_g).unwrap();
    println!("x = {:#?}", x);
    let cp = CompressedRistretto::from_slice(x.as_slice());
    println!("cp = {:#?}", cp);
    let rp = cp.decompress().expect("fail to decompress");
    println!("rp = {:#?}", rp);
}

#[test]
fn test_isk_calculation_initiator_responder() {
    let step1 =
        CPace::step1_debug(PASSWORD, CI, None::<&str>, SESSION_ID, &mut || Ok(y_a())).unwrap();
    let step2 = CPace::step2_debug(
        &step1.packet(),
        PASSWORD,
        CI,
        Some(AD_A),
        Some(AD_B),
        &mut || Ok(y_b()),
    )
    .unwrap();
    let step3 = step1.step3(&step2.packet(), Some(AD_A), Some(AD_B));
    let shared_keys = step3.unwrap();

    assert_eq!(shared_keys.k1, step2.shared_keys().k1);
    assert_eq!(shared_keys.k2, step2.shared_keys().k2);

    assert_eq!(
        String::from_iter([hex::encode(shared_keys.k1), hex::encode(shared_keys.k2)]),
        String::from_iter([
            "e91ccb2c0f5e0d0993a33956e3be59754f3f2b07db57631f5394452e",
            "a2e7b4354674eb1f5686c078462bf83bec72e8743df440108e638f35",
            "26d9b90e85be096f",
        ])
    );
}

mock! {
    Hash {}
}
