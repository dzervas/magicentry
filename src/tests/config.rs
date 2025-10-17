use crate::config::ConfigFile;
use uuid::Uuid;

#[test]
fn get_saml_key_strips_pem_headers() {
    let pem = "-----BEGIN PRIVATE KEY-----\nABCDEF\n-----END PRIVATE KEY-----\n";
    let path = std::env::temp_dir().join(format!("testkey-{}.pem", Uuid::new_v4()));
    std::fs::write(&path, pem).expect("write pem");

    let config = ConfigFile {
        saml_key_pem_path: path.to_string_lossy().into_owned(),
        ..Default::default()
    };

    let key = config.get_saml_key().expect("read key");
    assert_eq!(key, "ABCDEF");
}
