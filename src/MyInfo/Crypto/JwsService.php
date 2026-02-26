<?php

namespace MyInfo\Crypto;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer as JwsCompactSerializer;
use MyInfo\Exceptions\CryptoException;

/**
 * Verifies JWS payloads from MyInfo using RS256 against the MyInfo signing certificate.
 */
class JwsService
{
    /** @var JWSVerifier */
    private JWSVerifier $verifier;
    /** @var JWSLoader */
    private JWSLoader $loader;

    public function __construct()
    {
        $this->verifier = new JWSVerifier(new AlgorithmManager([new RS256()]));
        $serializerManager = new JWSSerializerManager([new JwsCompactSerializer()]);
        $this->loader = new JWSLoader($serializerManager, $this->verifier, null);
    }

    /**
     * Verify a compact-serialized JWS and return its payload as string.
     *
     * @throws CryptoException
     */
    public function verifyCompact(string $jws, string $publicCertPem): string
    {
        try {
            $jwk = JWKFactory::createFromX5C([$this->normalizeCertBody($publicCertPem)], [
                'use' => 'sig',
                'alg' => 'RS256',
                'kid' => 'myinfo-signing-cert',
            ]);

            $signatureIndex = 0;
            $loaded = $this->loader->loadAndVerifyWithKey($jws, $jwk, $signatureIndex);

            $headers = $loaded->getSignature($signatureIndex)->getProtectedHeader();
            if (($headers['alg'] ?? null) !== 'RS256') {
                throw new CryptoException('Unexpected JWS alg: ' . ($headers['alg'] ?? 'n/a'));
            }

            $payload = $loaded->getPayload();
            if ($payload === null) {
                throw new CryptoException('Verified JWS has empty payload.');
            }
            return $payload;
        } catch (\Throwable $e) {
            throw new CryptoException('JWS verification failed: ' . $e->getMessage());
        }
    }

    /**
     * Extract base64-encoded DER cert from PEM for x5c.
     */
    private function normalizeCertBody(string $pem): string
    {
        $pem = trim($pem);
        $pem = preg_replace('/\r|\n/', "\n", $pem);
        if (strpos($pem, 'BEGIN CERTIFICATE') !== false) {
            $pem = preg_replace('/-----BEGIN CERTIFICATE-----/', '', $pem);
            $pem = preg_replace('/-----END CERTIFICATE-----/', '', $pem);
            $pem = trim((string) $pem);
        }
        return $pem;
    }
}
