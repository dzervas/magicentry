document.addEventListener('DOMContentLoaded', function () {
	if ("credentials" in navigator === false) {
		console.log('WebAuthn not supported, disabling Passkey button');
		return;
	}

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
});

async function register() {
	const start_resp = await fetch('/webauthn/register/start', { method: 'POST' });
	const start_json = await start_resp.json();

	const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(start_json.publicKey);
	const finish_data = await navigator.credentials.create({ publicKey });

	const finish_resp = await fetch('/webauthn/register/finish', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(finish_data)
	});
	console.log(finish_resp);
}

async function authenticate() {
	const email = document.getElementById('email').value;

	if (!email) {
		document.getElementById('email-container').animate([
			{ transform: "translateX(4px)" },
			{ transform: "translateX(-4px)" },
		], {
			duration: 100,
			iterations: 4,
		});
		return;
	}

	const start_resp = await fetch('/webauthn/auth/start', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email: email }),
	});
	const start_json = await start_resp.json();

	const publicKey	= PublicKeyCredential.parseRequestOptionsFromJSON(start_json.publicKey);
	const finish_data = await navigator.credentials.get({ publicKey });

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
