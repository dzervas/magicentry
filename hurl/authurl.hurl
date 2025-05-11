# Click the "Login" button in the UI that the proxy redirected us to
POST http://localhost:8080/login?rd=http://localhost:8081/asdf?a=b
[Form]
email: valid@example.com
HTTP 200

# Set up a temporary webserver to serve the login link
# python3 -m http.server -d hurl 8081
GET http://localhost:8081/.link.txt
HTTP 200
[Captures]
link: body

# Visit the magic link that was sent
GET {{link}}
HTTP 302
[Captures]
session: cookie "session_id"
[Asserts]
# Here we check multiple things:
# - that the redirect origin is valid (according to the config)
# - that the whole url is kept is it was passed
# - that the existing query parameters are kept
# - that our custom `magicentry_code` query parameter was added
# - the code is populated and of the correct type
header "Location" startsWith "http://localhost:8081/asdf?a=b&magicentry_code=me_proxy_"

# Click the "Login" button in the UI that the proxy redirected us to
POST http://localhost:8080/login?rd=http://invalid.com/
[Form]
email: valid@example.com
HTTP 200

# Set up a temporary webserver to serve the login link
# python3 -m http.server -d hurl 8081
GET http://localhost:8081/.link.txt
HTTP 200
[Captures]
link: body

# Visit the magic link that was sent
GET {{link}}
HTTP 302
Location: /
