# Visit the login page
GET http://localhost:8080/login
HTTP 200
[Asserts]
xpath "//form[@method='post']" count == 1

# Click the "login" button
POST http://localhost:8080/login
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
[Captures]
session: cookie "session_id"

GET http://localhost:8080/
[Cookies]
session_id: {{session}}
HTTP 200
[Asserts]
body contains "valid@example.com"

GET http://localhost:8080/logout
[Cookies]
session_id: {{session}}
HTTP 302
Location: /login

# === Failure tests

# Check that link reuse doesn't work
GET {{link}}
HTTP 302
Location: /login

# Check that after logout, the session gets invalidated
GET http://localhost:8080/
[Cookies]
session_id: {{session}}
HTTP 302
Location: /login
