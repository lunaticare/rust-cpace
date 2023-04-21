use pake_cpace::CPace;

#[test]
fn test_cpace() {
    let client = CPace::step1("password", "client", "server", Some("ad")).unwrap();

    let step2 = CPace::step2(&client.packet(), "password", "client", "server", Some("ad")).unwrap();

    let shared_keys = client.step3(&step2.packet()).unwrap();

    assert_eq!(shared_keys.k1, step2.shared_keys().k1);
    assert_eq!(shared_keys.k2, step2.shared_keys().k2);
}
