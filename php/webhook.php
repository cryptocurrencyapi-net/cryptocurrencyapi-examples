<?php
// Checking that a callback (webhook) comes from the API.
//
// With a secret issued in your account, every callback carries two headers:
//   X-Nonce      the moment the attempt was sent, in milliseconds
//   X-Signature  HMAC-SHA256 of  nonce + "." + raw body, keyed by the secret, lowercase hex
//
// Put this file at your callback address, or try it locally:
//   WEBHOOK_SECRET=... php -S 0.0.0.0:8080 webhook.php
// It answers 200 to a genuine callback, 401 to anything else and 500 while WEBHOOK_SECRET is not set.
// Under php-fpm or Apache the environment of your shell does not reach PHP: set the variable in the pool
// (env[WEBHOOK_SECRET] = ...) or the virtual host (SetEnv), or read the secret from your own config.
// No extensions needed.

// $rawBody: the body exactly as it arrived. A decoded and re-encoded array has other bytes, and so
// another signature.
function verify_callback(string $secret, ?string $nonce, ?string $signature, string $rawBody): bool
{
    if ($secret === '' || !$nonce || !$signature) return false;
    $expected = hash_hmac('sha256', $nonce . '.' . $rawBody, $secret);
    // constant time: a plain comparison would tell how much of a forged signature is right
    return hash_equals($expected, $signature);
}

if (PHP_SAPI !== 'cli') {
    $body = file_get_contents('php://input');
    // PHP hands headers over as HTTP_<NAME> in $_SERVER
    $nonce = $_SERVER['HTTP_X_NONCE'] ?? null;
    $signature = $_SERVER['HTTP_X_SIGNATURE'] ?? null;
    $secret = (string)getenv('WEBHOOK_SECRET');
    if ($secret === '') {
        // not 401: with no secret every callback would be refused in silence
        error_log('webhook.php: WEBHOOK_SECRET is not set');
        http_response_code(500);
        exit;
    }
    if (!verify_callback($secret, $nonce, $signature, $body)) {
        http_response_code(401);
        exit;
    }
    // The same event may come again (after a chain reorganisation, with `reorg: true`): handling it
    // twice must do no harm. Before crediting, check the transaction and its confirmations yourself.
    error_log('callback ' . $body);
    http_response_code(200);
}
