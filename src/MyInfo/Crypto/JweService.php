<?php

namespace MyInfo\Crypto;

use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\CompactSerializer as JweCompactSerializer;
use MyInfo\Exceptions\CryptoException;

/**
 * Decrypts JWE payloads from MyInfo using RSA-OAEP + AES-GCM.
 */
class JweService
{
    /** @var JWEDecrypter */
    private JWEDecrypter $decrypter;
    /** @var JWELoader */
    private JWELoader $loader;

    public function __construct()
    {
        $this->decrypter = new JWEDecrypter([new RSAOAEP()], [new A256GCM()], []);
        $serializerManager = new JWESerializerManager([new JweCompactSerializer()]);
        $headerChecker = new HeaderCheckerManager([]);
        $this->loader = new JWELoader($serializerManager, $this->decrypter, $headerChecker);
    }

    /**
     * Decrypt a compact-serialized JWE string into raw payload (JWS string).
     *
     * @throws CryptoException
     */
    public function decryptCompact(string $jwe, string $privateKeyPem, ?string $passphrase = null): string
    {
        try {
            $jwk = JWKFactory::createFromKey($privateKeyPem, $passphrase, [
                'use' => 'enc',
                'alg' => 'RSA-OAEP',
                'kid' => 'client-key',
            ]);
            $loaded = $this->loader->loadAndDecryptWithKey($jwe, $jwk, $recipientIndex);

            if (!$loaded instanceof JWE) {
                throw new CryptoException('Invalid JWE structure.');
            }

            $headers = $loaded->getSharedProtectedHeader();
            if (($headers['alg'] ?? null) !== 'RSA-OAEP') {
                throw new CryptoException('Unexpected JWE alg: ' . ($headers['alg'] ?? 'n/a'));
            }
            if (($headers['enc'] ?? null) !== 'A256GCM') {
                throw new CryptoException('Unexpected JWE enc: ' . ($headers['enc'] ?? 'n/a'));
            }

            $payload = $loaded->getPayload();
            if ($payload === null) {
                throw new CryptoException('Decryption produced empty payload.');
            }
            return $payload;
        } catch (\Throwable $e) {
            throw new CryptoException('JWE decryption failed: ' . $e->getMessage());
        }
    }
}
