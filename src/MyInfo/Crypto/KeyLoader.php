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
        $pem = null;
        if ($path = $this->config->getSigningCertPath()) {
            if (!is_file($path)) {
                throw new ConfigException('Signing certificate not found at path: ' . $path);
            }
            $pem = (string) file_get_contents($path);
        } elseif ($b64 = $this->config->getSigningCertBase64()) {
            $pem = base64_decode($b64, true);
            if ($pem === false) {
                throw new ConfigException('Invalid base64 content for signing certificate.');
            }
        }

        if (!$pem || stripos($pem, 'BEGIN CERTIFICATE') === false) {
            throw new ConfigException('Signing certificate PEM is invalid or empty.');
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
}
