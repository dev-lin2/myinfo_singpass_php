<?php

namespace MyInfo\Crypto;

use MyInfo\Config;
use MyInfo\Exceptions\ConfigException;

/**
 * Loads and normalizes keys/certificates from config.
 *
 * Provides PEM strings for the MyInfo public certificate (JWS verification)
 * and the client's private key (JWE decryption).
 */
class KeyLoader
{
    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Returns the MyInfo signing certificate (PEM string) used to verify JWS.
     * @throws ConfigException
     */
    public function loadSigningCertPem(): string
    {
        $raw = null;
        if ($path = $this->config->getSigningCertPath()) {
            if (!is_file($path)) {
                throw new ConfigException('Signing certificate not found at path: ' . $path);
            }
            $raw = (string) file_get_contents($path);
        } elseif ($b64 = $this->config->getSigningCertBase64()) {
            $raw = base64_decode($b64, true);
            if ($raw === false) {
                throw new ConfigException('Invalid base64 content for signing certificate.');
            }
        }

        $pem = $raw !== null ? $this->normalizeCertificatePem($raw) : null;
        if (!$pem) {
            throw new ConfigException('Signing certificate is invalid. Provide a valid PEM/DER certificate.');
        }
        return $pem;
    }

    /**
     * Returns the client's decryption private key PEM for JWE decryption.
     * @throws ConfigException
     */
    public function loadDecryptionKeyPem(): string
    {
        $pem = null;
        if ($path = $this->config->getDecryptionKeyPath()) {
            if (!is_file($path)) {
                throw new ConfigException('Decryption private key not found at path: ' . $path);
            }
            $pem = (string) file_get_contents($path);
        } elseif ($b64 = $this->config->getDecryptionKeyBase64()) {
            $pem = base64_decode($b64, true);
            if ($pem === false) {
                throw new ConfigException('Invalid base64 content for decryption private key.');
            }
        }

        if (!$pem || stripos($pem, 'BEGIN') === false) {
            throw new ConfigException('Decryption private key PEM is invalid or empty.');
        }
        if (stripos($pem, 'BEGIN CERTIFICATE') !== false) {
            throw new ConfigException('Decryption key must be a private key, but a certificate was provided.');
        }
        return $pem;
    }

    /**
     * Returns the passphrase if provided, else null.
     */
    public function getDecryptionKeyPassphrase(): ?string
    {
        $pass = $this->config->getDecryptionKeyPassphrase();
        return $pass !== null && $pass !== '' ? $pass : null;
    }

    private function normalizeCertificatePem(string $raw): ?string
    {
        $trimmed = trim($raw);
        if ($trimmed === '') {
            return null;
        }

        // Already PEM
        if (stripos($trimmed, 'BEGIN CERTIFICATE') !== false) {
            return $this->isValidCertificatePem($trimmed) ? ($trimmed . "\n") : null;
        }

        // Accept base64 certificate body or binary DER certificate and convert to PEM.
        $bytes = $raw;
        if ($this->looksLikeBase64($trimmed)) {
            $decoded = base64_decode($trimmed, true);
            if ($decoded !== false && $decoded !== '') {
                $bytes = $decoded;
            }
        }

        $pem = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($bytes), 64, "\n")
            . "-----END CERTIFICATE-----\n";

        return $this->isValidCertificatePem($pem) ? $pem : null;
    }

    private function looksLikeBase64(string $value): bool
    {
        return preg_match('/^[A-Za-z0-9+\/=\r\n]+$/', $value) === 1;
    }

    private function isValidCertificatePem(string $pem): bool
    {
        $cert = @openssl_x509_read($pem);
        if ($cert === false) {
            return false;
        }

        if (is_resource($cert)) {
            @openssl_x509_free($cert);
        }

        return true;
    }
}
