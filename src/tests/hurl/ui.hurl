# Visit the login page
GET {{base_url}}/login
HTTP 200
[Asserts]
xpath "//form[@method='post']" count == 1

# Click the "login" button
POST {{base_url}}/login
[Form]
email: valid@example.com
HTTP 200

# Set up a temporary webserver to serve the login link
# python3 -m http.server -d hurl 8081
GET {{fixture_url}}
HTTP 200
[Captures]
link: body

# Visit the magic link that was sent
GET {{base_url}}{{link}}
HTTP 303
Location: /
[Captures]
session: cookie "session_id"

GET {{base_url}}/
[Cookies]
session_id: {{session}}
HTTP 200
[Asserts]
body contains "valid@example.com"

GET {{base_url}}/logout
[Cookies]
session_id: {{session}}
HTTP 303
Location: /login

# === Failure tests

# Check that after logout, the session gets invalidated
GET {{base_url}}/
[Cookies]
session_id: {{session}}
HTTP 302

# === Cookie cleanup tests

# Test that invalid session cookies get cleaned up
GET {{base_url}}/
[Cookies]
session_id: invalid_session_token
HTTP 302
[Asserts]
# Verify that Set-Cookie headers are present for cookie cleanup
header "Set-Cookie" exists
# Verify the first cookie (session_id) is being cleared
header "Set-Cookie" contains "session_id=; Max-Age=0"
