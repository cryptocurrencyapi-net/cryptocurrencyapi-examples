"""The whole cycle on two fresh addresses: create the keys, prepare a transfer of everything from the
first address to the second, sign it, send it. Every answer of the API is printed as it came.

    API_KEY=... python demo.py <chain>

A fresh address holds nothing, so at some step the API or the chain answers that there are no funds:
that is expected, the point is to see each step. Send some coins to address 1 and run it with that
key (PRIVATE_KEY=...) to see the transfer go through.
"""

import json
import os
import sys
import urllib.error
import urllib.request

from keys import FAMILY, generate_key, key_from_private
from sign import sign_hashes

API_URL = os.environ.get("API_URL", "https://api.cryptocurrencyapi.net")


def call(chain, method, body):
    request = urllib.request.Request(
        "%s/api/%s/%s" % (API_URL, chain, method),
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": os.environ["API_KEY"]},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            status, data = response.status, json.load(response)
    except urllib.error.HTTPError as e:
        status, data = e.code, json.load(e)
    # success is the HTTP status; a refusal is {"error": <code>, "values": {...}}
    print("\n%s → HTTP %d\n%s" % (method, status, json.dumps(data, indent=2)))
    return data if status == 200 else None


if len(sys.argv) != 2 or sys.argv[1] not in FAMILY or not os.environ.get("API_KEY"):
    sys.exit("usage: API_KEY=... python demo.py <chain>\nchains: " + " ".join(FAMILY))
chain = sys.argv[1]

# 1. Keys. In real life the private key is stored, safely: it is what signs
sender = key_from_private(chain, os.environ["PRIVATE_KEY"]) if os.environ.get("PRIVATE_KEY") else generate_key(chain)
recipient = generate_key(chain)
print("address 1, the sender:", json.dumps(sender, indent=2))
print("address 2, the recipient:", recipient["address"])

# 2. Prepare: the API builds the transaction and says what to sign
request = {"from": sender["address"], "to": recipient["address"], "amount": "max"}
# XRP signs over the public key; TON builds the wallet from it on the first send from an address
if chain in ("xrp", "ton"):
    request["public_key"] = sender["public_key"]
prepared = call(chain, "prepareTransaction", request)
if prepared is None:
    sys.exit(1)

# 3. Sign on your side: the private key never goes to the API
signatures = sign_hashes(chain, prepared["hashes"], sender["private_key"])
print("\nsignatures:", json.dumps(signatures, indent=2))

# 4. Send. A 503 with values.txid means the outcome is unknown: look that txid up with
# getTransactionByHash and repeat this same request if need be, but do not prepare the payment
# again, that could pay twice
call(chain, "sendPreparedTransaction", {"tx_id": prepared["tx_id"], "signatures": signatures})
