// Checking that a callback (webhook) comes from the API.
//
// With a secret issued in your account, every callback carries two headers:
//   X-Nonce      the moment the attempt was sent, in milliseconds
//   X-Signature  HMAC-SHA256 of  nonce + "." + raw body, keyed by the secret, lowercase hex
//
//   WEBHOOK_SECRET=... node webhook.js [port]    a receiver: 200 to a genuine callback, 401 to anything else

import { createHmac, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';

// rawBody: the body exactly as it arrived (a Buffer). A parsed and re-serialised object has other bytes,
// and so another signature.
export function verifyCallback(secret, nonce, signature, rawBody) {
  if (!secret || !nonce || !signature) return false;
  const expected = createHmac('sha256', secret).update(`${nonce}.`).update(rawBody).digest();
  const given = Buffer.from(String(signature), 'hex');
  // constant time: a plain comparison would tell how much of a forged signature is right
  return given.length === expected.length && timingSafeEqual(given, expected);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const secret = process.env.WEBHOOK_SECRET;
  if (!secret) {
    console.error('set WEBHOOK_SECRET to the secret from your account');
    process.exit(1);
  }
  createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      const body = Buffer.concat(chunks);
      // Node gives header names in lower case
      if (!verifyCallback(secret, request.headers['x-nonce'], request.headers['x-signature'], body)) {
        response.writeHead(401).end();
        return;
      }
      // The same event may come again (after a chain reorganisation, with `reorg: true`): handling it
      // twice must do no harm. Before crediting, check the transaction and its confirmations yourself.
      console.log('callback', body.toString());
      response.writeHead(200).end();
    });
  }).listen(Number(process.argv[2] || 8080));
}
