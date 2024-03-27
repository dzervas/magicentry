import { create, get, parseCreationOptionsFromJSON, parseRequestOptionsFromJSON, supported } from "@github/webauthn-json/browser-ponyfill";

document.addEventListener('DOMContentLoaded', function() {{
	if (!supported())
		return;

	const register_btn = document.getElementById('webauthn-register');
	const auth_btn = document.getElementById('webauthn-auth');

	if (register_btn !== null) {
		register_btn.classList.remove('hidden');
		register_btn.addEventListener('click', register);
	}

	if (auth_btn !== null) {
		auth_btn.classList.remove('hidden');
		auth_btn.addEventListener('click', authenticate);
	}
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

async function authenticate() {
	const email = document.getElementById('email').value;
	const start_resp = await fetch('/webauthn/auth/start', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: email }),
	});
	const start_json = await start_resp.json();

	const options = parseRequestOptionsFromJSON(start_json);
	const finish_data = await get(options);

	const finish_resp = await fetch('/webauthn/auth/finish', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(finish_data)
	});
	const finish_json = await finish_resp.json();
	console.log(finish_json);

	if (finish_resp.ok) {
		window.location.href = finish_json.redirect_to;
	}
	// TODO: Handle error
}
