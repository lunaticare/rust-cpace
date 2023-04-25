use std::iter::FromIterator;

use pake_cpace::util::prepend_len_vec;

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
