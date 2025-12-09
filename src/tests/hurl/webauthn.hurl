# WebAuthn End-to-End Test
# This test covers basic WebAuthn registration and authentication flow

# === Error Tests ===

# Test registration without browser session (should redirect to login)
POST {{base_url}}/webauthn/register/start
HTTP 302

# Test authentication with non-existent email
POST {{base_url}}/webauthn/auth/start
Content-Type: application/json
{
  "email": "nonexistent@example.com"
}
HTTP 302

# === Registration and Authentication Flow ===

# First, we need to get a browser session by logging in with a magic link
# This is required for WebAuthn registration

# Click the "Login" button in the UI that the proxy redirected us to
POST {{base_url}}/login?rd=http://localhost:8081/webauthn-test
[Form]
email: valid@example.com
HTTP 200

# Get the magic link from the fixture server
GET {{fixture_url}}
HTTP 200
[Captures]
link: body

# Visit the magic link that was sent
GET {{base_url}}{{link}}
HTTP 303
[Captures]
browser_session: cookie "session_id"

# Now we have a browser session, we can start WebAuthn registration
POST {{base_url}}/webauthn/register/start
Cookie: session_id={{browser_session}}
HTTP 200
[Captures]
reg_state: cookie "webauthn_registration"

# Get fake WebAuthn credential for testing
GET {{webauthn_fixture_url}}
HTTP 200

# Test WebAuthn authentication flow
# First, start authentication with the email
POST {{base_url}}/webauthn/auth/start
Content-Type: application/json
{
  "email": "valid@example.com"
}
HTTP 200
[Captures]
auth_state: cookie "webauthn_authentication"

# Test that the new session works
GET {{base_url}}/
Cookie: session_id={{browser_session}}
HTTP 200
