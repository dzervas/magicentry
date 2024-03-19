use std::fs;

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crate::{CONFIG, RANDOM_STRING_LEN};

pub fn get_partial(name: &str) -> String {
	let path_prefix = if CONFIG.path_prefix.ends_with('/') {
		&CONFIG.path_prefix[..CONFIG.path_prefix.len() - 1]
	} else {
		&CONFIG.path_prefix
	};

	let outer_content = fs::read_to_string("static/outer.html").expect("Unable to open static/outer.html");
	let inner_content = fs::read_to_string(format!("static/{}.html", name)).expect(format!("Unable to open static/{}.html", name).as_str());

	formatx::formatx!(
		outer_content,
		title = &CONFIG.title,
		path_prefix = path_prefix,
		content = inner_content
	).expect(format!("Unable to format static/outer.html with title `{:?}` and path_prefix `{:?}`", &CONFIG.title, path_prefix).as_str())
}

pub fn random_string() -> String {
	let mut rng = StdRng::from_entropy();
	let mut buffer = [0u8; RANDOM_STRING_LEN];
	rng.fill_bytes(&mut buffer);
	hex::encode(buffer)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_random_string() {
		let string1 = random_string();
		let string2 = random_string();

		assert_ne!(string1, string2);
		assert_eq!(string1.len(), RANDOM_STRING_LEN * 2);
	}
}
