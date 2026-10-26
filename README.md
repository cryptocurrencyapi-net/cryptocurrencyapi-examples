# CryptocurrencyAPI examples

How to send funds through [CryptocurrencyAPI](https://api.cryptocurrencyapi.net/docs) without ever giving it your
private key, in **JavaScript (Node.js)**, **Python** and **PHP**:

1. create a key pair and its address locally;
2. ask the API to prepare a transaction: it builds it and says what to sign;
3. sign that on your side;
4. send the signatures back: the API assembles the transaction and broadcasts it.

And, separately, how to check that a callback (webhook) really comes from the API.

| | JavaScript | Python | PHP |
|---|---|---|---|
| Keys and addresses | [js/keys.js](js/keys.js) | [python/keys.py](python/keys.py) | [php/keys.php](php/keys.php) |
| Signing | [js/sign.js](js/sign.js) | [python/sign.py](python/sign.py) | [php/sign.php](php/sign.php) |
| The whole cycle | [js/demo.js](js/demo.js) | [python/demo.py](python/demo.py) | [php/demo.php](php/demo.php) |
| Checking a callback | [js/webhook.js](js/webhook.js) | [python/webhook.py](python/webhook.py) | [php/webhook.php](php/webhook.php) |

Chains: `eth`, `pol`, `bsc`, `trx`, `btc`, `ltc`, `doge`, `bch`, `dash`, `sol`, `ton`, `xrp`.

## Setup

| | Needs | Install, in its directory |
|---|---|---|
| `js/` | Node.js 20.19+ | `npm install` |
| `python/` | Python 3.9+ | `pip install -r requirements.txt` |
| `php/` | PHP 7.4+ with the `gmp`, `sodium` and `curl` extensions | `composer install` |

## Keys

```bash
node keys.js eth            # or: python keys.py eth, php keys.php eth
node keys.js btc --segwit   # bc1... instead of 1... (BTC and LTC)
```

The answer has the same fields and formats as `POST /api/{chain}/generateAddress`, which can make the pair for you too.
**Store `private_key`**: it is what signs every transaction from the address, and nothing else can stand in for it.

| Chain | `private_key` | `public_key` | `address` and other fields |
|---|---|---|---|
| eth, pol, bsc | `0x` + 64 hex | `0x04…`, uncompressed | `0x…`, EIP-55 checksum |
| trx | `0x` + 64 hex | `0x04…`, uncompressed | `T…` |
| btc, ltc, doge, dash | 64 hex | compressed, 66 hex | `1…` / `L…` / `D…` / `X…`; BTC and LTC also SegWit `bc1q…` / `ltc1q…`; `address_type` |
| bch | 64 hex | compressed, 66 hex | `bitcoincash:q…`; `address_type` |
| sol | 64 hex, the ed25519 seed | 64 hex | Base58 of the public key |
| ton | 64 hex, the ed25519 seed | 64 hex | `UQ…`, wallet v4r2; `address_raw`: `0:…` |
| xrp | `ED` + 64 hex | `ED` + 64 hex | `r…`; `seed`: `sEd…`, the form wallets such as Xaman import |

## The whole cycle

```bash
API_KEY=... node demo.js eth     # or: python demo.py eth, php demo.php eth
```

The demo makes two fresh addresses and sends everything from the first to the second, printing every answer of the API.
A fresh address holds nothing, so `prepareTransaction` refuses at once with `insufficient_balance`: that is expected.
Send some coins to address 1 and run the demo again with `PRIVATE_KEY=<its key>` to see a transfer go through.

What it prints, on ETH (the private key is cut here):

```
address 1, the sender: {
  "address": "0xEAaE1e266c623FD6A81a6cEDe7529462D25C25E5",
  "private_key": "0x…",
  "public_key": "0x045d66f25e94b9649b50324f66822c1f52ef024902748c7eae7cacb5f77f0fc1a0613b824fd19695b1b08e61373f26022c44c5d6ceeda3ca09c5047f1927eaff2f"
}
address 2, the recipient: 0xa86469Bc50b3C2d5E7057EFADee00Df8b34aBcDd

prepareTransaction → HTTP 400
{
  "error": "insufficient_balance",
  "values": {
    "have": "0",
    "need": "0.000003822000000001"
  }
}
```

Here `need` is the gas plus 1 wei: the smallest balance that leaves something to send.

Success is the HTTP status, and the body holds only data: `sendPreparedTransaction` answers `{"result": "<txid>"}`.
A refusal is `{"error": <code>, "values": {...}}`.

**`503` with `values.txid`** means the outcome is unknown: a node that did not answer may have taken the transaction.
Look the txid up with `getTransactionByHash`. Repeating the same `sendPreparedTransaction` request is safe, but do not
prepare the payment again: that could pay twice.

XRP and TON need the sender's `public_key` in `prepareTransaction`, and the demo passes it. On XRP it is part of what
gets signed. On TON the first send from an address deploys the wallet contract, which is built from the key.

## Signing

`prepareTransaction` returns `hashes`. Each key is what to sign, and each value is the address whose key signs it.
`sendPreparedTransaction` takes `signatures`: the same keys, each with its signature.

| Chain | What is signed | Signature |
|---|---|---|
| eth, pol, bsc, trx | the 32-byte hash, secp256k1 | `0x` + 65 bytes hex: `r ‖ s ‖ recovery` |
| btc, ltc, doge, bch, dash | a 32-byte hash per input, secp256k1 | per hash `{"signature": DER hex, "public_key": compressed key hex}` |
| sol | **the message itself**, ed25519 | 64 bytes hex |
| ton | the 32-byte hash, ed25519 | 64 bytes hex |
| xrp | **the message itself**, ed25519 | 64 bytes hex |

Two things usually go wrong:

- **Do not hash again.** The bytes in `hashes` are ready to sign. Many libraries hash before signing by default:
  noble needs `prehash: false`, coincurve needs `hasher=None`.
- **The order of r, s and recovery.** noble's `format: 'recovered'` puts the recovery byte *first*, and the API wants
  it last. `sign.js` moves it.

## Checking a callback

When your account has a secret, every callback carries two headers:

```
X-Nonce: 1761495600123
X-Signature: hmac_sha256_hex(secret, X-Nonce + "." + raw_body)
```

```bash
WEBHOOK_SECRET=... node webhook.js 8080      # or: python webhook.py 8080, php -S 0.0.0.0:8080 webhook.php
```

The receiver answers `200` to a genuine callback and `401` to anything else. Two rules:

- **Check the body exactly as it arrived.** Do not parse it and serialise it again: the bytes would differ, and so would
  the signature.
- **Compare in constant time** (`timingSafeEqual`, `hmac.compare_digest`, `hash_equals`), not with `==`.

The same event may come again, for example after a chain reorganisation with `reorg: true`, so handling it twice must
do no harm. Any answer other than `2xx` is retried three times, after 5, 10 and 30 seconds, and then the notification
waits a day for `POST /api/webhooks/poll`. Every attempt carries a new `X-Nonce`: the same nonce twice means one attempt
reached you twice.

`webhook.php` answers `500` while `WEBHOOK_SECRET` is not set. Under php-fpm or Apache the environment of your shell
does not reach PHP: set the variable in the pool (`env[WEBHOOK_SECRET] = ...`) or the virtual host (`SetEnv`).
