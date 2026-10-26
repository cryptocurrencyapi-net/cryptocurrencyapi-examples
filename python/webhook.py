"""Checking that a callback (webhook) comes from the API.

With a secret issued in your account, every callback carries two headers:
  X-Nonce      the moment the attempt was sent, in milliseconds
  X-Signature  HMAC-SHA256 of  nonce + "." + raw body, keyed by the secret, lowercase hex

    WEBHOOK_SECRET=... python webhook.py [port]    a receiver: 200 to a genuine callback, 401 to anything else
"""

import hashlib
import hmac
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


def verify_callback(secret, nonce, signature, raw_body):
    """raw_body: the body exactly as it arrived (bytes). A parsed and re-serialised object has other
    bytes, and so another signature."""
    if not secret or not nonce or not signature:
        return False
    expected = hmac.new(secret.encode(), nonce.encode() + b"." + raw_body, hashlib.sha256).hexdigest()
    # constant time: a plain comparison would tell how much of a forged signature is right
    return hmac.compare_digest(expected.encode(), signature.encode())


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        # header names are case-insensitive here, as in most frameworks
        nonce, signature = self.headers.get("X-Nonce"), self.headers.get("X-Signature")
        if not verify_callback(os.environ["WEBHOOK_SECRET"], nonce, signature, body):
            self.send_response(401)
            self.end_headers()
            return
        # The same event may come again (after a chain reorganisation, with `reorg: true`): handling it
        # twice must do no harm. Before crediting, check the transaction and its confirmations yourself.
        print("callback", body.decode(), flush=True)
        self.send_response(200)
        self.end_headers()


if __name__ == "__main__":
    if not os.environ.get("WEBHOOK_SECRET"):
        sys.exit("set WEBHOOK_SECRET to the secret from your account")
    HTTPServer(("", int(sys.argv[1]) if len(sys.argv) > 1 else 8080), Receiver).serve_forever()
