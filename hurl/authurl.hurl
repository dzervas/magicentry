POST http://localhost:8080/login?rd=http://localhost:8081/
[Form]
email: valid@example.com
HTTP 200

# Set up a temporary webserver to serve the login link
# python3 -m http.server -d hurl 8081
GET http://localhost:8081/.link.txt
HTTP 200
[Captures]
link: body

GET {{link}}
HTTP 302
Location: http://localhost:8081/
[Captures]
session: cookie "session_id"
