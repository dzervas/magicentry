#![allow(clippy::unwrap_used)]
use std::path::PathBuf;
use std::fmt::Write;
use std::fs;

fn generate_hurl_tests() {
	let hurl_dir = PathBuf::from("src/tests/hurl");
	let gen_path = PathBuf::from("src/tests/gen_hurl_tests.rs");

	let mut code = String::new();

	for entry in fs::read_dir(&hurl_dir).unwrap() {
		let entry = entry.unwrap();
		let path = entry.path();
		if !path.is_file() {
			continue;
		}
		let name = path.file_stem().unwrap().to_string_lossy();
		let name_ident = name.replace('-', "_");
		let path_str = path.to_string_lossy();

		writeln!(code,
r#"
#[tokio::test]
async fn hurl_{name_ident}() {{ crate::tests::hurl::run_test("{path_str}").await; }}
"#,
		).unwrap();
	}

	fs::write(&gen_path, code).unwrap();
	println!("cargo:rerun-if-changed={}", hurl_dir.display());
}

fn main() {
	generate_hurl_tests();
}
