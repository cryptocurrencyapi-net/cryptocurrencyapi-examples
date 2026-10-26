"""Signs the `hashes` of prepareTransaction with your private key, the way sendPreparedTransaction
takes them back as `signatures`.

`hashes` maps what to sign to the address whose key signs it. What to sign is ready: never hash it
again. Mostly it is a 32-byte hash; on Solana, and on XRP with an ed25519 key, it is the message
itself, because ed25519 signs the message, not a hash of it.
"""

from coincurve import PrivateKey

from keys import FAMILY, ed25519_sign, key_from_private, strip0x


def sign_one(chain, what, key):
    message = bytes.fromhex(strip0x(what))
    family = FAMILY[chain]
    # an XRP key carries its algorithm in front: ED... or 00..., then the 32 bytes
    secret = bytes.fromhex(key["private_key"][2:] if family == "xrp" else strip0x(key["private_key"]))
    if family in ("evm", "tron"):
        # 65 bytes r || s || recovery; hasher=None: the hash is signed as it is
        return "0x" + PrivateKey(secret).sign_recoverable(message, hasher=None).hex()
    if family == "utxo":
        # every input on its own: a DER signature and the compressed public key
        return {"signature": PrivateKey(secret).sign(message, hasher=None).hex(), "public_key": key["public_key"]}
    if family in ("solana", "ton"):
        return ed25519_sign(secret, message).hex()
    if key["private_key"].startswith("ED"):  # xrp
        return ed25519_sign(secret, message).hex().upper()
    return PrivateKey(secret).sign(message, hasher=None).hex().upper()


def sign_hashes(chain, hashes, private_key):
    """hashes from the API + the sender's private key → the `signatures` of sendPreparedTransaction"""
    key = key_from_private(chain, private_key)
    return {what: sign_one(chain, what, key) for what in hashes}
