<?php
// The whole cycle on two fresh addresses: create the keys, prepare a transfer of everything from the
// first address to the second, sign it, send it. Every answer of the API is printed as it came.
//
//   API_KEY=... php demo.php <chain>
//
// A fresh address holds nothing, so at some step the API or the chain answers that there are no funds:
// that is expected, the point is to see each step. Send some coins to address 1 and run it with that
// key (PRIVATE_KEY=...) to see the transfer go through.

require_once __DIR__ . '/sign.php';

function api_call(string $chain, string $method, array $body): ?array
{
    $url = (getenv('API_URL') ?: 'https://api.cryptocurrencyapi.net') . "/api/$chain/$method";
    $curl = curl_init($url);
    curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($body, JSON_UNESCAPED_SLASHES),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-API-Key: ' . getenv('API_KEY')],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 60,
    ]);
    $data = json_decode((string)curl_exec($curl), true);
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    // success is the HTTP status; a refusal is {"error": <code>, "values": {...}}
    echo "\n$method → HTTP $status\n", json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    return $status === 200 ? $data : null;
}

$chain = $argv[1] ?? '';
if (!isset(Keys::FAMILY[$chain]) || !getenv('API_KEY')) {
    fwrite(STDERR, "usage: API_KEY=... php demo.php <chain>\nchains: " . implode(' ', array_keys(Keys::FAMILY)) . "\n");
    exit(1);
}

// 1. Keys. In real life the private key is stored, safely: it is what signs
$sender = getenv('PRIVATE_KEY') ? Keys::keyFromPrivate($chain, getenv('PRIVATE_KEY')) : Keys::generateKey($chain);
$recipient = Keys::generateKey($chain);
echo 'address 1, the sender: ', json_encode($sender, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
echo "address 2, the recipient: {$recipient['address']}\n";

// 2. Prepare: the API builds the transaction and says what to sign
$request = ['from' => $sender['address'], 'to' => $recipient['address'], 'amount' => 'max'];
// XRP signs over the public key; TON builds the wallet from it on the first send from an address
if ($chain === 'xrp' || $chain === 'ton') $request['public_key'] = $sender['public_key'];
$prepared = api_call($chain, 'prepareTransaction', $request);
if ($prepared === null) exit(1);

// 3. Sign on your side: the private key never goes to the API
$signatures = Sign::signHashes($chain, $prepared['hashes'], $sender['private_key']);
echo "\nsignatures: ", json_encode($signatures, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";

// 4. Send. A 503 with values.txid means the outcome is unknown: look that txid up with
// getTransactionByHash and repeat this same request if need be, but do not prepare the payment
// again, that could pay twice
api_call($chain, 'sendPreparedTransaction', ['tx_id' => $prepared['tx_id'], 'signatures' => $signatures]);
