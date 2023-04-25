use hmac_sha512::Hash;

pub fn prepend_len_closure<T: AsRef<[u8]>, F>(update: &mut F, input: T)
where
    F: FnMut(&[u8]) -> (),
{
    let input = input.as_ref();
    let mut length = input.len();
    loop {
        if length < 128 {
            update(&[length as u8]);
        } else {
            update(&[((length & 0x7f) + 0x80) as u8]);
        }
        length = length >> 7;
        if length == 0 {
            break;
        }
    }
    update(input);
}

pub fn prepend_len_hash<T: AsRef<[u8]>>(hash: &mut Hash, input: &T) {
    prepend_len_closure(&mut |i| hash.update(i), input);
}

pub fn prepend_len_vec<T: AsRef<[u8]>>(v: &mut Vec<u8>, input: &T) {
    prepend_len_closure(&mut |i| vec_push(v, i), input);
}

pub fn prepend_len_hash_vec<T: AsRef<[u8]>>(hash: &mut Hash, v: &mut Vec<u8>, input: &T) {
    prepend_len_hash(hash, input);
    prepend_len_vec(v, input);
}

pub fn vec_push<T: AsRef<[u8]>>(v: &mut Vec<u8>, b: T) {
    let b_ref = b.as_ref();
    for n in 0..b_ref.len() {
        v.push(b_ref[n]);
    }
}
