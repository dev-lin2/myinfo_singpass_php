<?php

namespace MyInfo;

use MyInfo\Exceptions\ConfigException;

/**
 * Configuration for the MyInfo integration.
 *
 * Supports loading from environment variables or from a Laravel config array.
 * Validates critical properties for either legacy MyInfo v3 flow or OIDC/FAPI flow.
 */
class Config
{
    /** @var string sandbox|test|prod */
    private string $environment;
    /** @var string legacy|oidc|oidc_fapi|fapi */
    private string $mode;

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
    /** @var array<string,mixed> */
    private array $oidc;

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
        int $timeoutMs = 10000,
        string $mode = 'legacy',
        array $oidc = []
    ) {
        $this->environment = $environment;
        $this->mode = strtolower(trim($mode)) !== '' ? strtolower(trim($mode)) : 'legacy';
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
        $this->oidc = $oidc;

        $this->validate();
    }

    /**
     * Build Config from environment variables.
     */
    public static function fromEnv(): self
    {
        $env = getenv('MYINFO_ENV') ?: 'sandbox';
        $mode = (string) (getenv('MYINFO_MODE') ?: 'legacy');

        // Canonical env keys are MYINFO_CLIENT_*, MYINFO_REDIRECT_URI, MYINFO_BASE_URL_*,
        // MYINFO_SIGNING_CERT_* and MYINFO_DECRYPTION_KEY_*.
        // Legacy keys remain as fallback for backward compatibility.
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
        $oidc = [
            'config_path' => getenv('MYINFO_OIDC_CONFIG_PATH') ?: null,
            'issuer_url' => getenv('MYINFO_ISSUER_URL') ?: 'https://stg-id.singpass.gov.sg/fapi',
            'scope' => getenv('MYINFO_SCOPES') ?: (getenv('MYINFO_SCOPE') ?: 'openid uinfin name'),
            'use_par' => getenv('MYINFO_OIDC_USE_PAR') ?: 'true',
            'use_dpop' => getenv('MYINFO_OIDC_USE_DPOP') ?: 'true',
            'private_sig_jwk_json' => getenv('MYINFO_OIDC_PRIVATE_SIG_JWK_JSON') ?: null,
            'private_sig_jwk_path' => getenv('MYINFO_OIDC_PRIVATE_SIG_JWK_PATH') ?: null,
            'public_sig_jwk_json' => getenv('MYINFO_OIDC_PUBLIC_SIG_JWK_JSON') ?: null,
            'public_sig_jwk_path' => getenv('MYINFO_OIDC_PUBLIC_SIG_JWK_PATH') ?: null,
            'private_enc_jwk_json' => getenv('MYINFO_OIDC_PRIVATE_ENC_JWK_JSON') ?: null,
            'private_enc_jwk_path' => getenv('MYINFO_OIDC_PRIVATE_ENC_JWK_PATH') ?: null,
        ];

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
            $timeoutMs,
            $mode,
            $oidc
        );
    }

    /**
     * Build Config from Laravel config array (config('myinfo')).
     * @param array<string,mixed> $cfg
     */
    public static function fromArray(array $cfg): self
    {
        $env = (string) ($cfg['env'] ?? 'sandbox');
        $mode = (string) ($cfg['mode'] ?? 'legacy');
        $attributes = $cfg['attributes'] ?? [];
        if (is_string($attributes)) {
            $attributes = self::parseAttributes($attributes);
        }
        $oidc = isset($cfg['oidc']) && is_array($cfg['oidc']) ? $cfg['oidc'] : [];

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
            (int) ($cfg['timeout_ms'] ?? 10000),
            $mode,
            $oidc
        );
    }

    /**
     * Validate critical configuration fields and basic URL shape.
     * @throws ConfigException
     */
    private function validate(): void
    {
        if ($this->clientId === '') {
            throw new ConfigException('MYINFO client_id is required.');
        }
        if ($this->redirectUri === '') {
            throw new ConfigException('MYINFO redirect_uri is required.');
        }
        foreach ([$this->authorizeUrl, $this->tokenUrl, $this->personUrl] as $url) {
            if ($url !== '' && !preg_match('/^https?:\/\//i', $url)) {
                throw new ConfigException('Invalid endpoint URL: ' . $url);
            }
        }

        if ($this->isOidcMode()) {
            // OIDC/FAPI flow uses private_key_jwt + JWK keys loaded separately in client runtime.
            return;
        }

        // Legacy MyInfo v3 flow validations
        if ($this->clientSecret === '') {
            throw new ConfigException('MYINFO client_secret is required for legacy mode.');
        }
        if ($this->purpose === '') {
            throw new ConfigException('MYINFO purpose is required.');
        }
        if (empty($this->attributes)) {
            throw new ConfigException('MYINFO attributes are required.');
        }
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
                return 'https://api.myinfo.gov.sg/com/v3/authorise';
            case 'test':
                return 'https://test.api.myinfo.gov.sg/com/v3/authorise';
            case 'sandbox':
            default:
                return 'https://sandbox.api.myinfo.gov.sg/com/v3/authorise';
        }
    }

    private static function defaultTokenUrl(string $env): string
    {
        switch (strtolower($env)) {
            case 'prod':
                return 'https://api.myinfo.gov.sg/com/v3/token';
            case 'test':
                return 'https://test.api.myinfo.gov.sg/com/v3/token';
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

    public function isOidcMode(): bool
    {
        return in_array($this->mode, ['oidc', 'oidc_fapi', 'fapi'], true);
    }

    // Getters (read-only config access)
    public function getEnvironment(): string { return $this->environment; }
    public function getMode(): string { return $this->mode; }
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
    /** @return array<string,mixed> */
    public function getOidc(): array { return $this->oidc; }
}
