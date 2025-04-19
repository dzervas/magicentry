use base64::{engine::general_purpose, Engine};
use flate2::read::DeflateDecoder;
use std::io::Read;

pub fn decode_saml_request(encoded_request: &str) -> Result<String, Box<dyn std::error::Error>> {
	let base64_decoded = general_purpose::STANDARD.decode(encoded_request)?;

	let mut decoder = DeflateDecoder::new(&base64_decoded[..]);
	let mut inflated_data = String::new();

	// Attempt to decompress
	match decoder.read_to_string(&mut inflated_data) {
		Ok(_) => Ok(inflated_data),
		Err(_) => {
			// If decompression fails, it might be just base64 encoded without deflate
			// (some implementations do this)
			String::from_utf8(base64_decoded).map_err(|e| e.into())
		}
	}
}
