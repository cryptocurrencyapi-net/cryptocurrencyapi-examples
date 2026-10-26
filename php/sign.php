<?php
// Signs the `hashes` of prepareTransaction with your private key, the way sendPreparedTransaction
// takes them back as `signatures`.
//
// `hashes` maps what to sign to the address whose key signs it. What to sign is ready: never hash it
// again. Mostly it is a 32-byte hash; on Solana, and on XRP with an ed25519 key, it is the message
// itself, because ed25519 signs the message, not a hash of it.

require_once __DIR__ . '/keys.php';

final class Sign
{
    private static function signOne(string $chain, string $what, array $key)
    {
        $message = Keys::strip0x($what);
        $family = Keys::FAMILY[$chain];
        // an XRP key carries its algorithm in front: ED... or 00..., then the 32 bytes
        $secret = strtolower($family === 'xrp' ? substr($key['private_key'], 2) : Keys::strip0x($key['private_key']));
        $ec = Keys::ec();
        switch ($family) {
            case 'evm':
            case 'tron':
                // 65 bytes r || s || recovery; canonical: low S, as the chains require
                $sig = $ec->sign($message, $ec->keyFromPrivate($secret, 'hex'), ['canonical' => true]);
                return '0x' . str_pad($sig->r->toString(16), 64, '0', STR_PAD_LEFT)
                    . str_pad($sig->s->toString(16), 64, '0', STR_PAD_LEFT) . sprintf('%02x', $sig->recoveryParam);
            case 'utxo':
                // every input on its own: a DER signature and the compressed public key
                $sig = $ec->sign($message, $ec->keyFromPrivate($secret, 'hex'), ['canonical' => true]);
                return ['signature' => $sig->toDER('hex'), 'public_key' => $key['public_key']];
            case 'solana':
            case 'ton':
                return bin2hex(Keys::ed25519Sign(hex2bin($secret), hex2bin($message)));
            default: // xrp
                $sig = substr($key['private_key'], 0, 2) === 'ED'
                    ? bin2hex(Keys::ed25519Sign(hex2bin($secret), hex2bin($message)))
                    : $ec->sign($message, $ec->keyFromPrivate($secret, 'hex'), ['canonical' => true])->toDER('hex');
                return strtoupper($sig);
        }
    }

    // hashes from the API + the sender's private key → the `signatures` of sendPreparedTransaction
    public static function signHashes(string $chain, array $hashes, string $privateKey): array
    {
        $key = Keys::keyFromPrivate($chain, $privateKey);
        $signatures = [];
        foreach (array_keys($hashes) as $what) {
            $signatures[$what] = self::signOne($chain, (string)$what, $key);
        }
        return $signatures;
    }
}
