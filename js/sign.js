// Signs the `hashes` of prepareTransaction with your private key, the way sendPreparedTransaction
// takes them back as `signatures`.
//
// `hashes` maps what to sign to the address whose key signs it. What to sign is ready: never hash it
// again. Mostly it is a 32-byte hash; on Solana, and on XRP with an ed25519 key, it is the message
// itself, because ed25519 signs the message, not a hash of it.

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js';
import { FAMILY, keyFromPrivate, strip0x } from './keys.js';

function signOne(chain, what, key) {
  const message = hexToBytes(strip0x(what));
  // an XRP key carries its algorithm in front: ED... or 00..., then the 32 bytes
  const secret = hexToBytes(FAMILY[chain] === 'xrp' ? key.private_key.slice(2) : strip0x(key.private_key));
  switch (FAMILY[chain]) {
    case 'evm':
    case 'tron': {
      // 65 bytes r || s || recovery; noble puts the recovery byte first, so it moves to the end
      const sig = secp256k1.sign(message, secret, { prehash: false, format: 'recovered' });
      return '0x' + bytesToHex(concatBytes(sig.subarray(1), sig.subarray(0, 1)));
    }
    case 'utxo':
      // every input on its own: a DER signature and the compressed public key
      return {
        signature: bytesToHex(secp256k1.sign(message, secret, { prehash: false, format: 'der' })),
        public_key: key.public_key,
      };
    case 'solana':
    case 'ton':
      return bytesToHex(ed25519.sign(message, secret));
    case 'xrp': {
      const sig = key.private_key.startsWith('ED')
        ? ed25519.sign(message, secret)
        : secp256k1.sign(message, secret, { prehash: false, format: 'der' });
      return bytesToHex(sig).toUpperCase();
    }
  }
}

// hashes from the API + the sender's private key → the `signatures` of sendPreparedTransaction
export function signHashes(chain, hashes, privateKey) {
  const key = keyFromPrivate(chain, privateKey);
  return Object.fromEntries(Object.keys(hashes).map((what) => [what, signOne(chain, what, key)]));
}
