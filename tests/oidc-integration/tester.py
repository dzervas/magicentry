import os
import requests
import threading
from authlib.integrations.requests_client import OAuth2Session
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# Environment variables for configuration
discovery_url = os.getenv("DISCOVERY_URL")
client_id = os.getenv("CLIENT_ID")
client_secret = os.getenv("CLIENT_SECRET")
redirect_uri = os.getenv("REDIRECT_URI")
session = requests.Session()


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        query_parameters = parse_qs(parsed_path.query)

        self.send_response(200)
        self.end_headers()

        resp = session.get(query_parameters["link"][0], allow_redirects=False)
        print(resp.headers)

        token = self.oidc_client.fetch_token(
            self.oidc_config["token_endpoint"], authorization_response=self.path
        )
        print(token)
        userinfo = self.oidc_client.get(
            self.oidc_client.metadata["userinfo_endpoint"], token=token
        )
        print(userinfo.json())


def init():
    response = requests.get(discovery_url)
    if response.status_code != 200:
        raise Exception("Failed to fetch OIDC configuration")
    oidc_config = response.json()
    setattr(SimpleHTTPRequestHandler, "oidc_config", oidc_config)

    oidc_client = OAuth2Session(
        client_id,
        client_secret,
        scope="openid email profile",
        redirect_uri=redirect_uri,
        issuer=oidc_config["issuer"],
        token_endpoint=oidc_config["token_endpoint"],
        userinfo_endpoint=oidc_config["userinfo_endpoint"],
        authorization_endpoint=oidc_config["authorization_endpoint"],
    )

    authorization_url, state = oidc_client.create_authorization_url(
        oidc_config["authorization_endpoint"],
    )
    setattr(SimpleHTTPRequestHandler, "oidc_client", oidc_client)

    server_address = ("0.0.0.0", 3333)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print("Server started at http://0.0.0.0:3333")
    try:
        threading.Thread(target=httpd.serve_forever).start()
    except KeyboardInterrupt:
        pass

    auth = session.get(authorization_url, allow_redirects=False)
    login_uri = auth.headers.get("location")
    session.post(login_uri, data={"email": "valid-integration@example.com"})

    httpd.shutdown()


if __name__ == "__main__":
    init()
