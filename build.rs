#![allow(clippy::unwrap_used)]
use std::path::PathBuf;
use std::fmt::Write;
use std::fs;
use std::process::Command;

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

fn compile_tailwind_css() {
	let input_path = PathBuf::from("static/main.css");
	let output_path = PathBuf::from("static/main.bundle.css");

	println!("cargo:rerun-if-changed={}", input_path.display());

	// Try to find and run tailwindcss CLI
	let result = Command::new("tailwindcss")
		.arg("-i")
		.arg(&input_path)
		.arg("-o")
		.arg(&output_path)
		.arg("--minify")
		.output();

	match result {
		Ok(output) => {
			if output.status.success() {
				println!("Successfully compiled Tailwind CSS to {}", output_path.display());
			} else {
				eprintln!("Tailwind CSS compilation failed:");
				eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
				eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
				panic!("Tailwind CSS compilation failed");
			}
		}
		Err(e) => {
			eprintln!("Failed to run tailwindcss command: {}", e);
			eprintln!("");
			eprintln!("Please ensure tailwindcss is installed and available in PATH");
			panic!("tailwindcss command not found");
		}
	}
}

fn main() {
	generate_hurl_tests();

	if cfg!(test) {
		println!("Skipping Tailwind compilation for rust-analyzer");
	} else {
		compile_tailwind_css();
	}

}
