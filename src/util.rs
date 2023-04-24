use hmac_sha512::Hash;

pub fn prepend_len(hash: &Hash, s: &str) {
    // let mut length = s.as_bytes().len();
    // while true {
    //     if length < 128 {
    //         hash.update([length as u8]);
    //     }
    // }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_prepend_len_1() {
        // assert_eq!(prepend_len([]), [0x00]);
    }
}
