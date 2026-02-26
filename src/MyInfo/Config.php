<?php

namespace MyInfo;

use MyInfo\Exceptions\ConfigException;

/**
 * Configuration for the MyInfo integration.
 *
 * Supports loading from environment variables or from a Laravel config array.
 * Validates critical properties (client credentials, endpoints, keys).
 */
class Config
{
    /** @var string sandbox|test|prod */
    private string $environment;
    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;
    private string $purpose;
    /** @var string[] */
    private array $attributes;

    private string $authorizeUrl;
    private string $tokenUrl;
    private string $personUrl;

    /** Path or base64 env for MyInfo signing certificate (verify JWS) */
    private ?string $signingCertPath;
    private ?string $signingCertBase64;

    /** Path or base64 env for client's decryption private key (decrypt JWE) */
    private ?string $decryptionKeyPath;
    private ?string $decryptionKeyBase64;
    private ?string $decryptionKeyPassphrase;

    private int $timeoutMs;

    public function __construct(
        string $environment,
        string $clientId,
        string $clientSecret,
        string $redirectUri,
        string $purpose,
        array $attributes,
        string $authorizeUrl,
        string $tokenUrl,
        string $personUrl,
        ?string $signingCertPath,
        ?string $signingCertBase64,
        ?string $decryptionKeyPath,
        ?string $decryptionKeyBase64,
        ?string $decryptionKeyPassphrase,
        int $timeoutMs = 10000
    ) {
        $this->environment = $environment;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
        $this->purpose = $purpose;
        $this->attributes = array_values(array_filter(array_map('trim', $attributes)));
        $this->authorizeUrl = $authorizeUrl;
        $this->tokenUrl = $tokenUrl;
        $this->personUrl = $personUrl;
        $this->signingCertPath = $signingCertPath;
        $this->signingCertBase64 = $signingCertBase64;
        $this->decryptionKeyPath = $decryptionKeyPath;
        $this->decryptionKeyBase64 = $decryptionKeyBase64;
        $this->decryptionKeyPassphrase = $decryptionKeyPassphrase;
        $this->timeoutMs = $timeoutMs;

        $this->validate();
    }

    /**
     * Build Config from environment variables.
     */
    public static function fromEnv(): self
    {
        $env = getenv('MYINFO_ENV') ?: 'sandbox';
        $clientId = (string) (getenv('MYINFO_CLIENT_ID') ?: getenv('MYINFO_APP_CLIENT_ID') ?: '');
        $clientSecret = (string) (getenv('MYINFO_CLIENT_SECRET') ?: getenv('MYINFO_APP_CLIENT_SECRET') ?: '');
        $redirectUri = (string) (getenv('MYINFO_REDIRECT_URI') ?: getenv('MYINFO_APP_REDIRECT_URL') ?: '');
        $purpose = (string) (getenv('MYINFO_PURPOSE') ?: 'demonstration');
        $attributes = self::parseAttributes(getenv('MYINFO_ATTRIBUTES') ?: 'name,uinfin,dob,sex,race,nationality');

        $authorizeUrl = (string) (
            getenv('MYINFO_BASE_URL_AUTH')
            ?: getenv('MYINFO_API_AUTHORISE')
            ?: self::defaultAuthorizeUrl($env)
        );
        $tokenUrl = (string) (
            getenv('MYINFO_TOKEN_URL')
            ?: getenv('MYINFO_API_TOKEN')
            ?: self::defaultTokenUrl($env)
        );
        $personUrl = (string) (
            getenv('MYINFO_BASE_URL_API')
            ?: getenv('MYINFO_API_PERSON')
            ?: self::defaultPersonUrl($env)
        );

        $timeoutMs = (int) (getenv('MYINFO_TIMEOUT_MS') ?: 10000);

        return new self(
            $env,
            $clientId,
            $clientSecret,
            $redirectUri,
            $purpose,
            $attributes,
            $authorizeUrl,
            $tokenUrl,
            $personUrl,
            // New names (preferred)
            (getenv('MYINFO_SIGNING_CERT_PATH') ?: null)
                ?: (getenv('MYINFO_PUBLIC_CERT_PATH') ?: null)
                ?: (getenv('MYINFO_SIGNATURE_CERT_PUBLIC_CERT') ?: null),
            (getenv('MYINFO_SIGNING_CERT_B64') ?: null) ?: (getenv('MYINFO_PUBLIC_CERT_B64') ?: null),
            (getenv('MYINFO_DECRYPTION_KEY_PATH') ?: null)
                ?: (getenv('MYINFO_PRIVATE_KEY_PATH') ?: null)
                ?: (getenv('DEMO_APP_SIGNATURE_CERT_PRIVATE_KEY') ?: null),
            (getenv('MYINFO_DECRYPTION_KEY_B64') ?: null) ?: (getenv('MYINFO_PRIVATE_KEY_B64') ?: null),
            (getenv('MYINFO_DECRYPTION_KEY_PASSPHRASE') ?: null) ?: (getenv('MYINFO_PRIVATE_KEY_PASSPHRASE') ?: null),
            $timeoutMs
        );
    }

    /**
     * Build Config from Laravel config array (config('myinfo')).
     * @param array<string,mixed> $cfg
     */
    public static function fromArray(array $cfg): self
    {
        $env = (string) ($cfg['env'] ?? 'sandbox');
        $attributes = $cfg['attributes'] ?? [];
        if (is_string($attributes)) {
            $attributes = self::parseAttributes($attributes);
        }

        return new self(
            (string) $env,
            (string) ($cfg['client_id'] ?? $cfg['app_client_id'] ?? ''),
            (string) ($cfg['client_secret'] ?? $cfg['app_client_secret'] ?? ''),
            (string) ($cfg['redirect_uri'] ?? $cfg['app_redirect_url'] ?? ''),
            (string) ($cfg['purpose'] ?? 'demonstration'),
            (array) $attributes,
            (string) ($cfg['authorize_url'] ?? $cfg['api_authorise_url'] ?? self::defaultAuthorizeUrl($env)),
            (string) ($cfg['token_url'] ?? $cfg['api_token_url'] ?? self::defaultTokenUrl($env)),
            (string) ($cfg['person_url'] ?? $cfg['api_person_url'] ?? self::defaultPersonUrl($env)),
            ($cfg['signing_cert_path'] ?? null) ?: ($cfg['public_cert_path'] ?? null) ?: ($cfg['signature_cert_public_cert'] ?? null),
            ($cfg['signing_cert_b64'] ?? null) ?: ($cfg['public_cert_b64'] ?? null),
            ($cfg['decryption_key_path'] ?? null) ?: ($cfg['private_key_path'] ?? null) ?: ($cfg['demo_app_signature_cert_private_key'] ?? null),
            ($cfg['decryption_key_b64'] ?? null) ?: ($cfg['private_key_b64'] ?? null),
            ($cfg['decryption_key_passphrase'] ?? null) ?: ($cfg['private_key_passphrase'] ?? null),
            (int) ($cfg['timeout_ms'] ?? 10000)
        );
    }

    /**
     * Validate critical configuration fields and basic URL shape.
     * @throws ConfigException
     */
    private function validate(): void
    {
        if ($this->clientId === '' || $this->clientSecret === '') {
            throw new ConfigException('MYINFO client_id/client_secret are required.');
        }
        if ($this->redirectUri === '') {
            throw new ConfigException('MYINFO redirect_uri is required.');
        }
        if ($this->purpose === '') {
            throw new ConfigException('MYINFO purpose is required.');
        }
        if (empty($this->attributes)) {
            throw new ConfigException('MYINFO attributes are required.');
        }
        foreach ([$this->authorizeUrl, $this->tokenUrl, $this->personUrl] as $url) {
            if (!preg_match('/^https?:\/\//i', $url)) {
                throw new ConfigException('Invalid endpoint URL: ' . $url);
            }
        }
        // Require at least one source for both keys
        if (!$this->signingCertPath && !$this->signingCertBase64) {
            throw new ConfigException('MyInfo signing certificate is required (path or base64).');
        }
        if (!$this->decryptionKeyPath && !$this->decryptionKeyBase64) {
            throw new ConfigException('Decryption private key is required (path or base64).');
        }
    }

    private static function parseAttributes(string $csv): array
    {
        if ($csv === '') {
            return [];
        }
        $parts = array_map('trim', explode(',', $csv));
        return array_values(array_filter($parts, static function ($v) {
            return $v !== '';
        }));
    }

    private static function defaultAuthorizeUrl(string $env): string
    {
        switch (strtolower($env)) {
            case 'prod':
                return 'https://login.singpass.gov.sg/singpass/myinfo/authorize';
            case 'test':
                return 'https://stg-id.singpass.gov.sg/singpass/myinfo/authorize';
            case 'sandbox':
            default:
                return 'https://sandbox.api.myinfo.gov.sg/com/v3/authorise';
        }
    }

    private static function defaultTokenUrl(string $env): string
    {
        switch (strtolower($env)) {
            case 'prod':
                return 'https://login.singpass.gov.sg/singpass/myinfo/token';
            case 'test':
                return 'https://stg-id.singpass.gov.sg/singpass/myinfo/token';
            case 'sandbox':
            default:
                return 'https://sandbox.api.myinfo.gov.sg/com/v3/token';
        }
    }

    private static function defaultPersonUrl(string $env): string
    {
        switch (strtolower($env)) {
            case 'prod':
                return 'https://api.myinfo.gov.sg/com/v3/person';
            case 'test':
                return 'https://test.api.myinfo.gov.sg/com/v3/person';
            case 'sandbox':
            default:
                return 'https://sandbox.api.myinfo.gov.sg/com/v3/person';
        }
    }

    // Getters (read-only config access)
    public function getEnvironment(): string { return $this->environment; }
    public function getClientId(): string { return $this->clientId; }
    public function getClientSecret(): string { return $this->clientSecret; }
    public function getRedirectUri(): string { return $this->redirectUri; }
    public function getPurpose(): string { return $this->purpose; }
    /** @return string[] */
    public function getAttributes(): array { return $this->attributes; }
    public function getAuthorizeUrl(): string { return $this->authorizeUrl; }
    public function getTokenUrl(): string { return $this->tokenUrl; }
    public function getPersonUrl(): string { return $this->personUrl; }
    public function getSigningCertPath(): ?string { return $this->signingCertPath; }
    public function getSigningCertBase64(): ?string { return $this->signingCertBase64; }
    public function getDecryptionKeyPath(): ?string { return $this->decryptionKeyPath; }
    public function getDecryptionKeyBase64(): ?string { return $this->decryptionKeyBase64; }
    public function getDecryptionKeyPassphrase(): ?string { return $this->decryptionKeyPassphrase; }
    public function getTimeoutMs(): int { return $this->timeoutMs; }
}
