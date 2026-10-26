<?php
// Key pairs and addresses for every chain of the API, computed locally.
//
// The result has the same fields and formats as POST /api/{chain}/generateAddress. Keep `private_key`:
// it is what signs your transactions later (see sign.php), and nothing else can stand in for it.
//
//   php keys.php <chain>            a new key pair
//   php keys.php btc --segwit       a bc1... address instead of 1... (BTC and LTC)
//
// Needs PHP 7.4+ with the gmp and sodium extensions, and `composer install`.

require_once __DIR__ . '/vendor/autoload.php';

use Elliptic\EC;
use kornrunner\Keccak;

final class Keys
{
    // How each chain signs. Chains of one family differ only in how an address is written.
    const FAMILY = [
        'eth' => 'evm', 'pol' => 'evm', 'bsc' => 'evm',
        'trx' => 'tron',
        'btc' => 'utxo', 'ltc' => 'utxo', 'doge' => 'utxo', 'bch' => 'utxo', 'dash' => 'utxo',
        'sol' => 'solana',
        'ton' => 'ton',
        'xrp' => 'xrp',
    ];

    const UTXO = [
        'btc' => ['version' => 0x00, 'hrp' => 'bc'],
        'ltc' => ['version' => 0x30, 'hrp' => 'ltc'],
        'doge' => ['version' => 0x1e],
        'dash' => ['version' => 0x4c],
        'bch' => ['cashaddr' => 'bitcoincash'],
    ];

    const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const BASE58_XRP = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
    const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

    private static $ec;

    public static function ec(): EC
    {
        return self::$ec ?: self::$ec = new EC('secp256k1');
    }

    public static function strip0x(string $hex): string
    {
        return strncasecmp($hex, '0x', 2) === 0 ? substr($hex, 2) : $hex;
    }

    private static function hash160(string $data): string
    {
        return hash('ripemd160', hash('sha256', $data, true), true);
    }

    private static function base58(string $data, string $alphabet = self::BASE58): string
    {
        $n = gmp_init(bin2hex($data), 16);
        $out = '';
        while (gmp_cmp($n, 0) > 0) {
            list($n, $r) = gmp_div_qr($n, 58);
            $out = $alphabet[gmp_intval($r)] . $out;
        }
        return str_repeat($alphabet[0], strlen($data) - strlen(ltrim($data, "\0"))) . $out;
    }

    private static function base58check(string $payload, string $alphabet = self::BASE58): string
    {
        return self::base58($payload . substr(hash('sha256', hash('sha256', $payload, true), true), 0, 4), $alphabet);
    }

    // 8-bit bytes → 5-bit groups, the last one padded with zeros
    private static function toWords(string $data): array
    {
        $acc = $bits = 0;
        $out = [];
        foreach (unpack('C*', $data) as $byte) {
            $acc = (($acc << 8) | $byte) & 0xffff;
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out[] = ($acc >> $bits) & 31;
            }
        }
        if ($bits) $out[] = ($acc << (5 - $bits)) & 31;
        return $out;
    }

    private static function polymod(array $values, array $generators, int $topShift, int $mask): int
    {
        $c = 1; // CashAddr checksums are 40 bits: PHP integers are 64-bit
        foreach ($values as $value) {
            $top = $c >> $topShift;
            $c = (($c & $mask) << 5) ^ $value;
            foreach ($generators as $i => $g) {
                if (($top >> $i) & 1) $c ^= $g;
            }
        }
        return $c ^ 1;
    }

    private static function charset(array $words): string
    {
        return implode('', array_map(function ($w) { return self::BECH32_CHARSET[$w]; }, $words));
    }

    private static function segwitAddress(string $hrp, string $publicKey): string
    {
        $data = array_merge([0], self::toWords(self::hash160($publicKey))); // witness version 0, P2WPKH
        $expanded = [];
        foreach (str_split($hrp) as $c) $expanded[] = ord($c) >> 5;
        $expanded[] = 0;
        foreach (str_split($hrp) as $c) $expanded[] = ord($c) & 31;
        $generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        $checksum = self::polymod(array_merge($expanded, $data, [0, 0, 0, 0, 0, 0]), $generators, 25, 0x1ffffff);
        for ($i = 0; $i < 6; $i++) $data[] = ($checksum >> 5 * (5 - $i)) & 31;
        return $hrp . '1' . self::charset($data);
    }

    // Bitcoin Cash writes a P2PKH address as CashAddr: bitcoincash:q...
    private static function cashAddress(string $prefix, string $publicKey): string
    {
        $words = self::toWords("\x00" . self::hash160($publicKey)); // version 0: P2PKH
        $values = [];
        foreach (str_split($prefix) as $c) $values[] = ord($c) & 31;
        $generators = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470];
        $checksum = self::polymod(array_merge($values, [0], $words, array_fill(0, 8, 0)), $generators, 35, 0x07ffffffff);
        for ($i = 0; $i < 8; $i++) $words[] = ($checksum >> 5 * (7 - $i)) & 31;
        return "$prefix:" . self::charset($words);
    }

    private static function utxoAddress(string $chain, string $publicKey, bool $segwit): string
    {
        $net = self::UTXO[$chain];
        if ($segwit) {
            if (!isset($net['hrp'])) throw new InvalidArgumentException("$chain has no SegWit addresses");
            return self::segwitAddress($net['hrp'], $publicKey);
        }
        if (isset($net['cashaddr'])) return self::cashAddress($net['cashaddr'], $publicKey);
        return self::base58check(chr($net['version']) . self::hash160($publicKey));
    }

    // ── EVM and TRON: Keccak-256 of the uncompressed public key, last 20 bytes ──

    private static function evmAddress(string $publicKey): string
    {
        $hex = substr(Keccak::hash(substr($publicKey, 1), 256), -40);
        $digest = Keccak::hash($hex, 256);
        // EIP-55: a letter is upper case where the hash of the lower-case address has a nibble >= 8
        $out = '';
        for ($i = 0; $i < 40; $i++) $out .= hexdec($digest[$i]) >= 8 ? strtoupper($hex[$i]) : $hex[$i];
        return "0x$out";
    }

    private static function tronAddress(string $publicKey): string
    {
        return self::base58check("\x41" . substr(Keccak::hash(substr($publicKey, 1), 256, true), -20));
    }

    // ── TON: the address of a wallet is the hash of its initial state (code + data), wallet v4r2 ──

    const TON_CODE_HASH = 'feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0';
    const TON_CODE_DEPTH = 7;
    const TON_SUBWALLET_ID = 698983191;

    private static function tonAddress(string $publicKey): array
    {
        // data cell: seqno 0, subwallet_id, the key, an empty plugin dictionary (one 0 bit, then the end bit)
        $data = hash('sha256', "\x00" . chr(81) . pack('NN', 0, self::TON_SUBWALLET_ID) . $publicKey . "\x40", true);
        // state_init cell: bits 00110 (code and data present) + end bit, then the depths and hashes of both
        $stateInit = hash('sha256', "\x02\x01\x34" . pack('nn', self::TON_CODE_DEPTH, 0) . hex2bin(self::TON_CODE_HASH)
            . $data, true);
        // user-friendly form: non-bounceable (0x51), workchain 0, the hash, CRC16-XMODEM
        $body = "\x51\x00" . $stateInit;
        $crc = 0;
        foreach (unpack('C*', $body) as $byte) {
            $crc ^= $byte << 8;
            for ($i = 0; $i < 8; $i++) $crc = $crc & 0x8000 ? (($crc << 1) ^ 0x1021) & 0xffff : ($crc << 1) & 0xffff;
        }
        return [
            'address' => strtr(base64_encode($body . pack('n', $crc)), '+/', '-_'),
            'address_raw' => '0:' . bin2hex($stateInit),
        ];
    }

    // ── Solana, TON and XRP keys: ed25519, the private key is a 32-byte seed ──

    public static function ed25519PublicKey(string $seed): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
    }

    public static function ed25519Sign(string $seed, string $message): string
    {
        $secretKey = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
        return sodium_crypto_sign_detached($message, $secretKey);
    }

    // elliptic-php takes any number as a key and reduces it modulo n, so 1 <= d < n is checked here
    private static function checkSecp256k1Range(string $hex): void
    {
        $d = gmp_init($hex, 16);
        if (gmp_cmp($d, 0) <= 0 || gmp_cmp($d, gmp_init(self::ec()->n->toString(16), 16)) >= 0) {
            throw new InvalidArgumentException('invalid private key: out of the secp256k1 range');
        }
    }

    private static function xrpAddress(string $publicKey): string
    {
        return self::base58check("\x00" . self::hash160($publicKey), self::BASE58_XRP);
    }

    // ── Public API ──

    // A stored private key → the answer generateAddress gives for it (no seed: it cannot be recovered)
    public static function keyFromPrivate(string $chain, string $privateKey, bool $segwit = false): array
    {
        $key = trim($privateKey);
        if (!isset(self::FAMILY[$chain])) throw new InvalidArgumentException("unknown chain: $chain");
        $family = self::FAMILY[$chain];
        if ($family === 'xrp') {
            $hex = strtoupper(self::strip0x($key));
            if (preg_match('/^ED[0-9A-F]{64}$/', $hex)) {
                $publicKey = "\xed" . self::ed25519PublicKey(hex2bin(substr($hex, 2)));
            } elseif (preg_match('/^(00)?[0-9A-F]{64}$/', $hex)) {
                // a secp256k1 key, as older XRP wallets have: 00 + 32 bytes
                $hex = '00' . substr($hex, -64);
                self::checkSecp256k1Range(substr($hex, 2));
                $publicKey = hex2bin(self::ec()->keyFromPrivate(substr($hex, 2), 'hex')->getPublic(true, 'hex'));
            } else {
                throw new InvalidArgumentException('invalid XRP private key: expected ED + 64 hex or 00 + 64 hex');
            }
            return ['address' => self::xrpAddress($publicKey), 'private_key' => $hex, 'public_key' => strtoupper(bin2hex($publicKey))];
        }
        if (!preg_match('/^(0x)?[0-9a-fA-F]{64}$/', $key)) {
            throw new InvalidArgumentException('invalid private key: expected 64 hex characters');
        }
        $secret = strtolower(self::strip0x($key));
        if ($family === 'solana' || $family === 'ton') {
            $publicKey = self::ed25519PublicKey(hex2bin($secret));
            $keys = ['private_key' => $secret, 'public_key' => bin2hex($publicKey)];
            return $family === 'ton' ? self::tonAddress($publicKey) + $keys : ['address' => self::base58($publicKey)] + $keys;
        }
        self::checkSecp256k1Range($secret);
        $pair = self::ec()->keyFromPrivate($secret, 'hex');
        if ($family === 'utxo') {
            $publicKey = hex2bin($pair->getPublic(true, 'hex'));
            return [
                'address' => self::utxoAddress($chain, $publicKey, $segwit),
                'private_key' => $secret,
                'public_key' => bin2hex($publicKey),
                'address_type' => $segwit ? 'segwit' : 'legacy',
            ];
        }
        $publicKey = hex2bin($pair->getPublic(false, 'hex'));
        return [
            'address' => $family === 'tron' ? self::tronAddress($publicKey) : self::evmAddress($publicKey),
            'private_key' => "0x$secret",
            'public_key' => '0x' . bin2hex($publicKey),
        ];
    }

    // A new key pair. XRP: a seed too (sEd...), the form wallets such as Xaman import.
    public static function generateKey(string $chain, bool $segwit = false): array
    {
        $family = self::FAMILY[$chain] ?? null;
        if ($family === 'xrp') {
            $entropy = random_bytes(16);
            $privateKey = 'ED' . strtoupper(bin2hex(substr(hash('sha512', $entropy, true), 0, 32)));
            return self::keyFromPrivate($chain, $privateKey) + ['seed' => self::base58check("\x01\xe1\x4b" . $entropy, self::BASE58_XRP)];
        }
        if ($family === 'solana' || $family === 'ton') return self::keyFromPrivate($chain, bin2hex(random_bytes(32)));
        // a random 32 bytes is a valid secp256k1 key but for a chance of about 2^-128
        return self::keyFromPrivate($chain, bin2hex(random_bytes(32)), $segwit);
    }
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    if (!isset($argv[1], Keys::FAMILY[$argv[1]])) {
        fwrite(STDERR, "usage: php keys.php <chain> [--segwit]\nchains: " . implode(' ', array_keys(Keys::FAMILY)) . "\n");
        exit(1);
    }
    $pair = Keys::generateKey($argv[1], in_array('--segwit', $argv, true));
    echo json_encode($pair, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
}
