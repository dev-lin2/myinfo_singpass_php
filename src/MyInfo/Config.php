<?php

namespace MyInfo;

use MyInfo\Exceptions\ConfigException;

/**
 * FAPI 2.0 only configuration for Singpass/Myinfo v5.
 */
class Config
{
    private string $clientId;
    private string $redirectUri;
    private int $timeoutMs;
    /** @var array<string,mixed> */
    private array $oidc;

    /**
     * @param array<string,mixed> $oidc
     */
    public function __construct(string $clientId, string $redirectUri, int $timeoutMs = 10000, array $oidc = [])
    {
        $this->clientId = trim($clientId);
        $this->redirectUri = trim($redirectUri);
        $this->timeoutMs = $timeoutMs;
        $this->oidc = $oidc;

        $this->validate();
    }

    /**
     * Build Config from environment variables.
     */
    public static function fromEnv(): self
    {
        return new self(
            (string) (getenv('MYINFO_CLIENT_ID') ?: ''),
            (string) (getenv('MYINFO_REDIRECT_URI') ?: ''),
            (int) (getenv('MYINFO_TIMEOUT_MS') ?: 10000),
            [
                'config_path' => getenv('MYINFO_OIDC_CONFIG_PATH') ?: null,
                'issuer_url' => getenv('MYINFO_ISSUER_URL') ?: 'https://stg-id.singpass.gov.sg/fapi',
                'scope' => getenv('MYINFO_SCOPES') ?: 'openid uinfin name',
                'client_assertion_audience' => getenv('MYINFO_OIDC_CLIENT_ASSERTION_AUDIENCE') ?: null,
                'retry_attempts' => getenv('MYINFO_OIDC_RETRY_ATTEMPTS') ?: '3',
                'retry_backoff_ms' => getenv('MYINFO_OIDC_RETRY_BACKOFF_MS') ?: '250',
                'private_sig_jwk_json' => getenv('MYINFO_OIDC_PRIVATE_SIG_JWK_JSON') ?: null,
                'private_sig_jwk_path' => getenv('MYINFO_OIDC_PRIVATE_SIG_JWK_PATH') ?: null,
                'public_sig_jwk_json' => getenv('MYINFO_OIDC_PUBLIC_SIG_JWK_JSON') ?: null,
                'public_sig_jwk_path' => getenv('MYINFO_OIDC_PUBLIC_SIG_JWK_PATH') ?: null,
                'private_enc_jwk_json' => getenv('MYINFO_OIDC_PRIVATE_ENC_JWK_JSON') ?: null,
                'private_enc_jwk_path' => getenv('MYINFO_OIDC_PRIVATE_ENC_JWK_PATH') ?: null,
                'verification_jwks_json' => getenv('MYINFO_OIDC_VERIFICATION_JWKS_JSON') ?: null,
                'verification_jwks_path' => getenv('MYINFO_OIDC_VERIFICATION_JWKS_PATH') ?: null,
            ]
        );
    }

    /**
     * Build Config from Laravel config array (config('myinfo')).
     * @param array<string,mixed> $cfg
     */
    public static function fromArray(array $cfg): self
    {
        $oidc = isset($cfg['oidc']) && is_array($cfg['oidc']) ? $cfg['oidc'] : [];

        return new self(
            (string) ($cfg['client_id'] ?? ''),
            (string) ($cfg['redirect_uri'] ?? ''),
            (int) ($cfg['timeout_ms'] ?? 10000),
            $oidc
        );
    }

    /**
     * Validate critical configuration fields.
     * @throws ConfigException
     */
    private function validate(): void
    {
        if ($this->clientId === '') {
            throw new ConfigException('MYINFO_CLIENT_ID is required.');
        }

        if ($this->redirectUri === '') {
            throw new ConfigException('MYINFO_REDIRECT_URI is required.');
        }

        if (!preg_match('/^https?:\/\//i', $this->redirectUri)) {
            throw new ConfigException('MYINFO_REDIRECT_URI must be an http/https URL.');
        }

        if ($this->timeoutMs < 1) {
            throw new ConfigException('MYINFO_TIMEOUT_MS must be greater than 0.');
        }
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    public function getTimeoutMs(): int
    {
        return $this->timeoutMs;
    }

    /** @return array<string,mixed> */
    public function getOidc(): array
    {
        return $this->oidc;
    }
}
