// Key pairs and addresses for every chain of the API, computed locally.
//
// The result has the same fields and formats as POST /api/{chain}/generateAddress. Keep `private_key`:
// it is what signs your transactions later (see sign.js), and nothing else can stand in for it.
//
//   node keys.js <chain>            a new key pair
//   node keys.js btc --segwit       a bc1... address instead of 1... (BTC and LTC)

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { bytesToHex, hexToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';
import { base58, base58xrp, base64urlnopad, bech32 } from '@scure/base';
import { fileURLToPath } from 'node:url';

// How each chain signs. Chains of one family differ only in how an address is written.
export const FAMILY = {
  eth: 'evm', pol: 'evm', bsc: 'evm',
  trx: 'tron',
  btc: 'utxo', ltc: 'utxo', doge: 'utxo', bch: 'utxo', dash: 'utxo',
  sol: 'solana',
  ton: 'ton',
  xrp: 'xrp',
};

const UTXO = {
  btc: { version: 0x00, hrp: 'bc' },
  ltc: { version: 0x30, hrp: 'ltc' },
  doge: { version: 0x1e },
  dash: { version: 0x4c },
  bch: { cashaddr: 'bitcoincash' },
};

export const strip0x = (hex) => hex.replace(/^0x/i, '');
const hash160 = (data) => ripemd160(sha256(data));
const base58check = (payload, alphabet = base58) =>
  alphabet.encode(concatBytes(payload, sha256(sha256(payload)).subarray(0, 4)));

// ── EVM and TRON: Keccak-256 of the uncompressed public key, last 20 bytes ──

function evmAddress(publicKey) {
  const hex = bytesToHex(keccak_256(publicKey.subarray(1)).subarray(-20));
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(hex)));
  // EIP-55: a letter is upper case where the hash of the lower-case address has a nibble >= 8
  return '0x' + [...hex].map((c, i) => (parseInt(hash[i], 16) >= 8 ? c.toUpperCase() : c)).join('');
}

function tronAddress(publicKey) {
  return base58check(concatBytes(new Uint8Array([0x41]), keccak_256(publicKey.subarray(1)).subarray(-20)));
}

// ── Bitcoin and its forks: hash160 of the compressed public key ──

const CASHADDR_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function cashAddrPolymod(values) {
  const generators = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let c = 1n;
  for (const value of values) {
    const top = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(value);
    generators.forEach((g, i) => { if ((top >> BigInt(i)) & 1n) c ^= g; });
  }
  return c ^ 1n;
}

// Bitcoin Cash writes a P2PKH address as CashAddr: bitcoincash:q...
function cashAddress(prefix, publicKey) {
  const words = bech32.toWords(concatBytes(new Uint8Array([0x00]), hash160(publicKey))); // version 0: P2PKH
  const prefixWords = [...prefix].map((c) => c.charCodeAt(0) & 31);
  const checksum = cashAddrPolymod([...prefixWords, 0, ...words, 0, 0, 0, 0, 0, 0, 0, 0]);
  const tail = Array.from({ length: 8 }, (_, i) => Number((checksum >> BigInt(5 * (7 - i))) & 31n));
  return `${prefix}:` + [...words, ...tail].map((w) => CASHADDR_CHARSET[w]).join('');
}

function utxoAddress(chain, publicKey, segwit) {
  const net = UTXO[chain];
  if (segwit) {
    if (!net.hrp) throw new Error(`${chain} has no SegWit addresses`);
    return bech32.encode(net.hrp, [0, ...bech32.toWords(hash160(publicKey))]); // witness v0, P2WPKH
  }
  if (net.cashaddr) return cashAddress(net.cashaddr, publicKey);
  return base58check(concatBytes(new Uint8Array([net.version]), hash160(publicKey)));
}

// ── TON: the address of a wallet is the hash of its initial state (code + data), wallet v4r2 ──

const TON_CODE_HASH = hexToBytes('feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0');
const TON_CODE_DEPTH = 7;
const TON_SUBWALLET_ID = 698983191;

function tonAddress(publicKey) {
  // data cell: seqno 0, subwallet_id, the key, an empty plugin dictionary (one 0 bit, then the end bit)
  const u32 = (n) => new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  const data = sha256(concatBytes(new Uint8Array([0x00, 81]), u32(0), u32(TON_SUBWALLET_ID), publicKey, new Uint8Array([0x40])));
  // state_init cell: bits 00110 (code and data present) + end bit, then the depths and hashes of both
  const stateInit = sha256(concatBytes(new Uint8Array([0x02, 0x01, 0x34, 0, TON_CODE_DEPTH, 0, 0]), TON_CODE_HASH, data));
  // user-friendly form: non-bounceable (0x51), workchain 0, the hash, CRC16-XMODEM
  const body = concatBytes(new Uint8Array([0x51, 0x00]), stateInit);
  let crc = 0;
  for (const byte of body) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return { address: base64urlnopad.encode(concatBytes(body, new Uint8Array([crc >> 8, crc & 255]))), address_raw: `0:${bytesToHex(stateInit)}` };
}

// ── XRP: ed25519 keys from a seed of 16 random bytes ──

function xrpAddress(publicKey) {
  return base58check(concatBytes(new Uint8Array([0x00]), hash160(publicKey)), base58xrp);
}

// ── Public API ──

// A stored private key → the answer generateAddress gives for it (no seed: it cannot be recovered)
export function keyFromPrivate(chain, privateKey, { segwit = false } = {}) {
  const key = privateKey.trim();
  const family = FAMILY[chain];
  if (!family) throw new Error(`unknown chain: ${chain}`);
  if (family === 'xrp') {
    const hex = strip0x(key).toUpperCase();
    if (/^ED[0-9A-F]{64}$/.test(hex)) {
      const publicKey = concatBytes(new Uint8Array([0xed]), ed25519.getPublicKey(hexToBytes(hex.slice(2))));
      return { address: xrpAddress(publicKey), private_key: hex, public_key: bytesToHex(publicKey).toUpperCase() };
    }
    // a secp256k1 key, as older XRP wallets have: 00 + 32 bytes
    if (!/^(00)?[0-9A-F]{64}$/.test(hex)) throw new Error('invalid XRP private key: expected ED + 64 hex or 00 + 64 hex');
    const publicKey = secp256k1.getPublicKey(hexToBytes(hex.slice(-64)), true);
    return { address: xrpAddress(publicKey), private_key: '00' + hex.slice(-64), public_key: bytesToHex(publicKey).toUpperCase() };
  }
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(key)) throw new Error('invalid private key: expected 64 hex characters');
  const secret = hexToBytes(strip0x(key));
  if (family === 'solana' || family === 'ton') {
    const publicKey = ed25519.getPublicKey(secret);
    const keys = { private_key: bytesToHex(secret), public_key: bytesToHex(publicKey) };
    return family === 'ton' ? { ...tonAddress(publicKey), ...keys } : { address: base58.encode(publicKey), ...keys };
  }
  if (!secp256k1.utils.isValidSecretKey(secret)) throw new Error('invalid private key: out of the secp256k1 range');
  if (family === 'utxo') {
    const publicKey = secp256k1.getPublicKey(secret, true);
    return {
      address: utxoAddress(chain, publicKey, segwit),
      private_key: bytesToHex(secret),
      public_key: bytesToHex(publicKey),
      address_type: segwit ? 'segwit' : 'legacy',
    };
  }
  const publicKey = secp256k1.getPublicKey(secret, false);
  return {
    address: family === 'tron' ? tronAddress(publicKey) : evmAddress(publicKey),
    private_key: '0x' + bytesToHex(secret),
    public_key: '0x' + bytesToHex(publicKey),
  };
}

// A new key pair. XRP: a seed too (sEd...), the form wallets such as Xaman import.
export function generateKey(chain, { segwit = false } = {}) {
  switch (FAMILY[chain]) {
    case 'xrp': {
      const entropy = randomBytes(16);
      const privateKey = 'ED' + bytesToHex(sha512(entropy).subarray(0, 32)).toUpperCase();
      const seed = base58check(concatBytes(new Uint8Array([0x01, 0xe1, 0x4b]), entropy), base58xrp);
      return { ...keyFromPrivate(chain, privateKey), seed };
    }
    case 'solana':
    case 'ton':
      return keyFromPrivate(chain, bytesToHex(ed25519.utils.randomSecretKey()));
    default:
      return keyFromPrivate(chain, bytesToHex(secp256k1.utils.randomSecretKey()), { segwit });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const chain = process.argv[2];
  if (!FAMILY[chain]) {
    console.error(`usage: node keys.js <chain> [--segwit]\nchains: ${Object.keys(FAMILY).join(' ')}`);
    process.exit(1);
  }
  console.log(JSON.stringify(generateKey(chain, { segwit: process.argv.includes('--segwit') }), null, 2));
}
