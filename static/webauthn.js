import { create, parseCreationOptionsFromJSON, supported } from "@github/webauthn-json/browser-ponyfill";

document.addEventListener('DOMContentLoaded', function() {{
	if (!supported())
		return;

	const register_btn = document.getElementById('webauthn-register');
	register_btn.classList.remove('hidden');
	register_btn.addEventListener('click', register);
}});

async function register() {
	const start_resp = await fetch('/webauthn/register/start', { method: 'POST' });
	const start_json = await start_resp.json();

	const options = parseCreationOptionsFromJSON(start_json);
	const finish_data = await create(options);

	const finish_resp = await fetch('/webauthn/register/finish', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(finish_data)
	});
	console.log(finish_resp);
}
