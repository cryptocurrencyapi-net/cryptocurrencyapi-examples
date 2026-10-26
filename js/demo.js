// The whole cycle on two fresh addresses: create the keys, prepare a transfer of everything from the
// first address to the second, sign it, send it. Every answer of the API is printed as it came.
//
//   API_KEY=... node demo.js <chain>
//
// A fresh address holds nothing, so at some step the API or the chain answers that there are no funds:
// that is expected, the point is to see each step. Send some coins to address 1 and run it with that
// key (PRIVATE_KEY=...) to see the transfer go through.

import { FAMILY, generateKey, keyFromPrivate } from './keys.js';
import { signHashes } from './sign.js';

const API_URL = process.env.API_URL || 'https://api.cryptocurrencyapi.net';

async function call(chain, method, body) {
  const response = await fetch(`${API_URL}/api/${chain}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': process.env.API_KEY },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  const data = await response.json();
  // success is the HTTP status; a refusal is { error: <code>, values: {...} }
  console.log(`\n${method} → HTTP ${response.status}\n${JSON.stringify(data, null, 2)}`);
  return response.ok ? data : null;
}

const chain = process.argv[2];
if (!FAMILY[chain] || !process.env.API_KEY) {
  console.error(`usage: API_KEY=... node demo.js <chain>\nchains: ${Object.keys(FAMILY).join(' ')}`);
  process.exit(1);
}

// 1. Keys. In real life the private key is stored, safely: it is what signs
const sender = process.env.PRIVATE_KEY ? keyFromPrivate(chain, process.env.PRIVATE_KEY) : generateKey(chain);
const recipient = generateKey(chain);
console.log('address 1, the sender:', JSON.stringify(sender, null, 2));
console.log('address 2, the recipient:', recipient.address);

// 2. Prepare: the API builds the transaction and says what to sign
const request = { from: sender.address, to: recipient.address, amount: 'max' };
// XRP signs over the public key; TON builds the wallet from it on the first send from an address
if (chain === 'xrp' || chain === 'ton') request.public_key = sender.public_key;
const prepared = await call(chain, 'prepareTransaction', request);
if (!prepared) process.exit(1);

// 3. Sign on your side: the private key never goes to the API
const signatures = signHashes(chain, prepared.hashes, sender.private_key);
console.log('\nsignatures:', JSON.stringify(signatures, null, 2));

// 4. Send. A 503 with values.txid means the outcome is unknown: look that txid up with
// getTransactionByHash and repeat this same request if need be, but do not prepare the payment
// again, that could pay twice
await call(chain, 'sendPreparedTransaction', { tx_id: prepared.tx_id, signatures });
