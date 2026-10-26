"""Key pairs and addresses for every chain of the API, computed locally.

The result has the same fields and formats as POST /api/{chain}/generateAddress. Keep `private_key`:
it is what signs your transactions later (see sign.py), and nothing else can stand in for it.

    python keys.py <chain>            a new key pair
    python keys.py btc --segwit       a bc1... address instead of 1... (BTC and LTC)
"""

import base64
import hashlib
import json
import os
import re
import struct
import sys

from coincurve import PrivateKey
from Crypto.Hash import RIPEMD160, keccak
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

# How each chain signs. Chains of one family differ only in how an address is written.
FAMILY = {
    "eth": "evm", "pol": "evm", "bsc": "evm",
    "trx": "tron",
    "btc": "utxo", "ltc": "utxo", "doge": "utxo", "bch": "utxo", "dash": "utxo",
    "sol": "solana",
    "ton": "ton",
    "xrp": "xrp",
}  # fmt: skip

UTXO = {
    "btc": {"version": 0x00, "hrp": "bc"},
    "ltc": {"version": 0x30, "hrp": "ltc"},
    "doge": {"version": 0x1E},
    "dash": {"version": 0x4C},
    "bch": {"cashaddr": "bitcoincash"},
}

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_XRP = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def strip0x(value):
    return value[2:] if value[:2].lower() == "0x" else value


def sha256(data):
    return hashlib.sha256(data).digest()


def keccak256(data):
    return keccak.new(digest_bits=256, data=data).digest()


def hash160(data):
    return RIPEMD160.new(sha256(data)).digest()


def base58_encode(data, alphabet=BASE58):
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return alphabet[0] * (len(data) - len(data.lstrip(b"\0"))) + out


def base58check(payload, alphabet=BASE58):
    return base58_encode(payload + sha256(sha256(payload))[:4], alphabet)


def to_words(data):
    """8-bit bytes → 5-bit groups, the last one padded with zeros."""
    acc, bits, out = 0, 0, []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def polymod(values, generators, top_shift, mask):
    c = 1
    for value in values:
        top = c >> top_shift
        c = ((c & mask) << 5) ^ value
        for i, g in enumerate(generators):
            if (top >> i) & 1:
                c ^= g
    return c ^ 1


def segwit_address(hrp, public_key):
    data = [0] + to_words(hash160(public_key))  # witness version 0, P2WPKH
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    checksum = polymod(expanded + data + [0] * 6, generators, 25, 0x1FFFFFF)
    data += [(checksum >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data)


def cash_address(prefix, public_key):
    """Bitcoin Cash writes a P2PKH address as CashAddr: bitcoincash:q..."""
    words = to_words(b"\x00" + hash160(public_key))  # version 0: P2PKH
    generators = [0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470]
    checksum = polymod([ord(c) & 31 for c in prefix] + [0] + words + [0] * 8, generators, 35, 0x07FFFFFFFF)
    words += [(checksum >> 5 * (7 - i)) & 31 for i in range(8)]
    return prefix + ":" + "".join(BECH32_CHARSET[w] for w in words)


# ── EVM and TRON: Keccak-256 of the uncompressed public key, last 20 bytes ──


def evm_address(public_key):
    hex_address = keccak256(public_key[1:])[-20:].hex()
    digest = keccak256(hex_address.encode()).hex()
    # EIP-55: a letter is upper case where the hash of the lower-case address has a nibble >= 8
    return "0x" + "".join(c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(hex_address))


def tron_address(public_key):
    return base58check(b"\x41" + keccak256(public_key[1:])[-20:])


def utxo_address(chain, public_key, segwit):
    net = UTXO[chain]
    if segwit:
        if "hrp" not in net:
            raise ValueError("%s has no SegWit addresses" % chain)
        return segwit_address(net["hrp"], public_key)
    if "cashaddr" in net:
        return cash_address(net["cashaddr"], public_key)
    return base58check(bytes([net["version"]]) + hash160(public_key))


# ── TON: the address of a wallet is the hash of its initial state (code + data), wallet v4r2 ──

TON_CODE_HASH = bytes.fromhex("feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0")
TON_CODE_DEPTH = 7
TON_SUBWALLET_ID = 698983191


def ton_address(public_key):
    # data cell: seqno 0, subwallet_id, the key, an empty plugin dictionary (one 0 bit, then the end bit)
    data = sha256(bytes([0x00, 81]) + struct.pack(">II", 0, TON_SUBWALLET_ID) + public_key + b"\x40")
    # state_init cell: bits 00110 (code and data present) + end bit, then the depths and hashes of both
    state_init = sha256(bytes([0x02, 0x01, 0x34]) + struct.pack(">HH", TON_CODE_DEPTH, 0) + TON_CODE_HASH + data)
    # user-friendly form: non-bounceable (0x51), workchain 0, the hash, CRC16-XMODEM
    body = b"\x51\x00" + state_init
    crc = 0
    for byte in body:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    friendly = base64.urlsafe_b64encode(body + struct.pack(">H", crc)).decode()
    return {"address": friendly, "address_raw": "0:" + state_init.hex()}


# ── Solana, TON and XRP keys: ed25519, the private key is a 32-byte seed ──


def ed25519_public_key(seed):
    return ECC.construct(curve="Ed25519", seed=seed).public_key().export_key(format="raw")


def ed25519_sign(seed, message):
    return eddsa.new(ECC.construct(curve="Ed25519", seed=seed), "rfc8032").sign(message)


def xrp_address(public_key):
    return base58check(b"\x00" + hash160(public_key), BASE58_XRP)


# ── Public API ──


def key_from_private(chain, private_key, segwit=False):
    """A stored private key → the answer generateAddress gives for it (no seed: it cannot be recovered)"""
    key = private_key.strip()
    family = FAMILY.get(chain)
    if family is None:
        raise ValueError("unknown chain: %s" % chain)
    if family == "xrp":
        hex_key = strip0x(key).upper()
        if re.fullmatch(r"ED[0-9A-F]{64}", hex_key):
            public_key = b"\xed" + ed25519_public_key(bytes.fromhex(hex_key[2:]))
            return {"address": xrp_address(public_key), "private_key": hex_key, "public_key": public_key.hex().upper()}
        # a secp256k1 key, as older XRP wallets have: 00 + 32 bytes
        if not re.fullmatch(r"(00)?[0-9A-F]{64}", hex_key):
            raise ValueError("invalid XRP private key: expected ED + 64 hex or 00 + 64 hex")
        public_key = PrivateKey(bytes.fromhex(hex_key[-64:])).public_key.format(compressed=True)
        return {
            "address": xrp_address(public_key),
            "private_key": "00" + hex_key[-64:],
            "public_key": public_key.hex().upper(),
        }
    if not re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", key):
        raise ValueError("invalid private key: expected 64 hex characters")
    secret = bytes.fromhex(strip0x(key))
    if family in ("solana", "ton"):
        public_key = ed25519_public_key(secret)
        keys = {"private_key": secret.hex(), "public_key": public_key.hex()}
        return dict(ton_address(public_key), **keys) if family == "ton" else dict(address=base58_encode(public_key), **keys)
    signer = PrivateKey(secret)  # raises on a key out of the secp256k1 range
    if family == "utxo":
        public_key = signer.public_key.format(compressed=True)
        return {
            "address": utxo_address(chain, public_key, segwit),
            "private_key": secret.hex(),
            "public_key": public_key.hex(),
            "address_type": "segwit" if segwit else "legacy",
        }
    public_key = signer.public_key.format(compressed=False)
    return {
        "address": tron_address(public_key) if family == "tron" else evm_address(public_key),
        "private_key": "0x" + secret.hex(),
        "public_key": "0x" + public_key.hex(),
    }


def generate_key(chain, segwit=False):
    """A new key pair. XRP: a seed too (sEd...), the form wallets such as Xaman import."""
    family = FAMILY.get(chain)
    if family == "xrp":
        entropy = os.urandom(16)
        pair = key_from_private(chain, "ED" + hashlib.sha512(entropy).digest()[:32].hex())
        pair["seed"] = base58check(b"\x01\xe1\x4b" + entropy, BASE58_XRP)
        return pair
    if family in ("solana", "ton"):
        return key_from_private(chain, os.urandom(32).hex())
    return key_from_private(chain, PrivateKey().secret.hex(), segwit)


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in FAMILY:
        sys.exit("usage: python keys.py <chain> [--segwit]\nchains: " + " ".join(FAMILY))
    print(json.dumps(generate_key(sys.argv[1], "--segwit" in sys.argv), indent=2))
