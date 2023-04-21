use pake_cpace::CPace;

#[test]
fn test_cpace() {
    let client = CPace::step1("password", "client", "server", Some("ad")).unwrap();

    let step2 = CPace::step2(&client.packet(), "password", "client", "server", Some("ad")).unwrap();

    let shared_keys = client.step3(&step2.packet()).unwrap();

    assert_eq!(shared_keys.k1, step2.shared_keys().k1);
    assert_eq!(shared_keys.k2, step2.shared_keys().k2);
}

const tc_PRS: [u8; 8] = [0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64];
const tc_CI: [u8; 22] = [
    0x0a, 0x41, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72, 0x0a, 0x42, 0x72, 0x65, 0x73,
    0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72,
];
const tc_sid: [u8; 16] = [
    0x7e, 0x4b, 0x47, 0x91, 0xd6, 0xa8, 0xef, 0x01, 0x9b, 0x93, 0x6c, 0x79, 0xfb, 0x7f, 0x2c, 0x57,
];
const tc_g: [u8; 32] = [
    0x9c, 0x57, 0x12, 0x17, 0x85, 0x70, 0x95, 0x72, 0x04, 0xd8, 0x9a, 0xc1, 0x1a, 0xcb, 0xef, 0x78,
    0x9d, 0xd0, 0x76, 0x99, 0x2b, 0xa3, 0x61, 0x42, 0x9a, 0xcb, 0x2b, 0xc3, 0x8c, 0x71, 0xd1, 0x4c,
];
const tc_ya: [u8; 32] = [
    0x14, 0x33, 0xdd, 0x19, 0x35, 0x99, 0x92, 0xd4, 0xe0, 0x6d, 0x74, 0x0d, 0x39, 0x93, 0xd4, 0x29,
    0xaf, 0x63, 0x38, 0xff, 0xb4, 0x53, 0x1c, 0xe1, 0x75, 0xd2, 0x24, 0x49, 0x85, 0x3a, 0x79, 0x0b,
];
const tc_ADa: [u8; 3] = [0x41, 0x44, 0x61];
const tc_Ya: [u8; 32] = [
    0xa8, 0xfc, 0x42, 0xc4, 0xd5, 0x7b, 0x3c, 0x73, 0x46, 0x66, 0x10, 0x11, 0x12, 0x2a, 0x00, 0x56,
    0x3d, 0x09, 0x95, 0xfd, 0x72, 0xb6, 0x21, 0x23, 0xae, 0x24, 0x44, 0x00, 0xe8, 0x6d, 0x7b, 0x1a,
];
const tc_yb: [u8; 32] = [
    0x0e, 0x65, 0x66, 0xd3, 0x2d, 0x80, 0xa5, 0xa1, 0x13, 0x5f, 0x99, 0xc2, 0x7f, 0x2d, 0x63, 0x7a,
    0xa2, 0x4d, 0xa2, 0x30, 0x27, 0xc3, 0xfa, 0x76, 0xb9, 0xd1, 0xcf, 0xd9, 0x74, 0x2f, 0xdc, 0x00,
];
const tc_ADb: [u8; 3] = [0x41, 0x44, 0x62];
const tc_Yb: [u8; 32] = [
    0xfc, 0x8e, 0x84, 0xae, 0x4a, 0xb7, 0x25, 0x90, 0x9a, 0xf0, 0x5a, 0x56, 0xef, 0x97, 0x14, 0xdb,
    0x69, 0x30, 0xe4, 0xa5, 0x58, 0x9b, 0x3f, 0xee, 0x6c, 0xdd, 0x26, 0x62, 0x36, 0x67, 0x6d, 0x63,
];
const tc_K: [u8; 32] = [
    0x3e, 0xfe, 0xf1, 0x70, 0x6f, 0x42, 0xef, 0xa3, 0x54, 0x02, 0x0b, 0x08, 0x7b, 0x37, 0xfb, 0xd9,
    0xf8, 0x1c, 0xf7, 0x2a, 0x16, 0xf4, 0x94, 0x7e, 0x4a, 0x04, 0x2a, 0x7f, 0x1a, 0xaa, 0x2b, 0x6f,
];
const tc_ISK_IR: [u8; 64] = [
    0x0e, 0x33, 0xc5, 0x82, 0x2b, 0xd4, 0x95, 0xde, 0xa9, 0x4b, 0xa7, 0xaf, 0x16, 0x15, 0x01, 0xf1,
    0xb2, 0xd6, 0xa1, 0x6d, 0x46, 0x4b, 0x5d, 0x6e, 0x1a, 0x53, 0xdc, 0xbf, 0xb9, 0x24, 0x4b, 0x9b,
    0xa6, 0x6c, 0x09, 0xc4, 0x30, 0xff, 0xfd, 0xfe, 0x4f, 0xb4, 0xe9, 0x9b, 0x4e, 0xa4, 0x6f, 0x99,
    0x1a, 0x27, 0x2d, 0xe0, 0x43, 0x1c, 0x13, 0x2c, 0x2c, 0x79, 0xfd, 0x6d, 0xe1, 0xa7, 0xe5, 0xe4,
];
const tc_ISK_SY: [u8; 64] = [
    0xca, 0x36, 0x33, 0x5b, 0xe6, 0x82, 0xa4, 0x80, 0xa9, 0xfc, 0x63, 0x97, 0x7d, 0x04, 0x4a, 0x10,
    0xff, 0x7a, 0xdf, 0xcd, 0xa0, 0xf2, 0x97, 0x8f, 0xbc, 0xf8, 0x71, 0x3d, 0x2a, 0x4e, 0x23, 0xe2,
    0x5c, 0x05, 0xa9, 0xa0, 0x2e, 0xdc, 0xfb, 0xff, 0x2e, 0xde, 0x65, 0xb7, 0x52, 0xf8, 0xea, 0x1f,
    0x44, 0x54, 0xd7, 0x64, 0xad, 0x8e, 0xd8, 0x60, 0x7c, 0x15, 0x8e, 0xf6, 0x62, 0x61, 0x45, 0x67,
];
