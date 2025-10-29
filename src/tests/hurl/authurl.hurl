# Click the "Login" button in the UI that the proxy redirected us to
POST {{base_url}}/login?rd=http://localhost:8081/asdf?a=b
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
[Captures]
session: cookie "session_id"
proxy_link: header "Location"
[Asserts]
# Here we check multiple things:
# - that the redirect origin is valid (according to the config)
# - that the whole url is kept is it was passed
# - that the existing query parameters are kept
# - that our custom `magicentry_code` query parameter was added
# - the code is populated and of the correct type
header "Location" startsWith "http://localhost:8081/asdf?a=b&magicentry_code=me_pc_"

# Make the initial request after returning to the service
GET {{base_url}}/auth-url/status
X-Original-Url: {{proxy_link}}
HTTP 200
[Asserts]
cookie "magicentry_session_id" startsWith "me_ps_"

# The magicentry_session_id cookie is held in the cookiejar and is sent
GET {{base_url}}/auth-url/status
X-Original-Url: http://localhost:8081/asdasdasdas
HTTP 200

# === Failure tests

# Click the "Login" button in the UI that the proxy redirected us to
# but test an invalid return address
POST {{base_url}}/login?rd=http://invalid.com/
[Form]
email: valid@example.com
HTTP 200

GET {{fixture_url}}
HTTP 200
[Captures]
link: body

# Visit the magic link that was sent
GET {{base_url}}{{link}}
HTTP 303
Location: /
