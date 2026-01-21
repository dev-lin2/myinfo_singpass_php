<?php

namespace MyInfo;

use MyInfo\Crypto\JweService;
use MyInfo\Crypto\JwsService;
use MyInfo\Crypto\KeyLoader;
use MyInfo\DTO\AccessToken;
use MyInfo\DTO\Person;
use MyInfo\Exceptions\OAuthException;
use MyInfo\Http\HttpClient;
use Carbon\CarbonImmutable;

/**
 * High-level MyInfo API client: builds authorize URL, exchanges tokens, fetches person data.
 */
class MyInfoClient
{
    private Config $config;
    private HttpClient $http;
    private KeyLoader $keyLoader;
    private JweService $jwe;
    private JwsService $jws;

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->http = new HttpClient($config->getTimeoutMs());
        $this->keyLoader = new KeyLoader($config);
        $this->jwe = new JweService();
        $this->jws = new JwsService();
    }

    /**
     * Build a MyInfo authorization URL for redirecting the user.
     * @param array<string,string> $overrides Optional param overrides (state, nonce, attributes, purpose).
     */
    public function buildAuthorizeUrl(array $overrides = []): string
    {
        $params = [
            'client_id' => $this->config->getClientId(),
            'attributes' => implode(',', $overrides['attributes'] ?? $this->config->getAttributes()),
            'purpose' => $overrides['purpose'] ?? $this->config->getPurpose(),
            'redirect_uri' => $this->config->getRedirectUri(),
            'state' => $overrides['state'] ?? bin2hex(random_bytes(8)),
            'nonce' => $overrides['nonce'] ?? bin2hex(random_bytes(8)),
            'response_type' => 'code',
        ];
        return $this->config->getAuthorizeUrl() . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Exchange the authorization code for an access token.
     *
     * @throws OAuthException
     */
    public function exchangeToken(string $code): AccessToken
    {
        $res = $this->http->postForm($this->config->getTokenUrl(), [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->config->getRedirectUri(),
            'client_id' => $this->config->getClientId(),
            'client_secret' => $this->config->getClientSecret(),
        ]);

        $body = json_decode((string) $res->getBody(), true);
        if (!is_array($body) || empty($body['access_token'])) {
            throw new OAuthException('Invalid token response.');
        }
        $expiresIn = isset($body['expires_in']) ? (int) $body['expires_in'] : 300;
        $expiresAt = CarbonImmutable::now()->addSeconds(max(1, $expiresIn));
        return new AccessToken((string) $body['access_token'], $expiresAt, $body['token_type'] ?? null, $body['scope'] ?? null);
    }

    /**
     * Fetch the person data for the given access token and decrypt+verify the payload.
     * Optionally pass `$uinfin` to support person endpoints that require a path parameter.
     *
     * @param string $accessToken OAuth access token
     * @param array<string>|null $attributes Optional attribute list to request
     * @param string|null $uinfin Optional UIN/FIN if your endpoint requires it in the path
     */
    public function getPerson(string $accessToken, ?array $attributes = null, ?string $uinfin = null): Person
    {
        $attrs = $attributes ? implode(',', $attributes) : implode(',', $this->config->getAttributes());
        $headers = [
            'Authorization' => 'Bearer ' . $accessToken,
            'Accept' => 'application/json',
        ];

        $url = $this->config->getPersonUrl();
        if ($uinfin !== null) {
            if (strpos($url, '{uinfin}') !== false) {
                $url = str_replace('{uinfin}', rawurlencode($uinfin), $url);
            } elseif (preg_match('!/person/?$!i', $url)) {
                $url = rtrim($url, '/') . '/' . rawurlencode($uinfin);
            }
        }

        $res = $this->http->get($url, ['attributes' => $attrs], $headers);
        $body = json_decode((string) $res->getBody(), true);

        // The person API returns a nested JWE (compact) containing a JWS (compact) of JSON payload.
        $jwe = is_array($body) && isset($body['data']) ? (string) $body['data'] : null;
        if (!$jwe) {
            // some environments may return the compact string directly
            $jwe = is_string($res->getBody()) ? (string) $res->getBody() : null;
        }
        if (!$jwe) {
            throw new \RuntimeException('Unexpected person API response');
        }

        $privateKeyPem = $this->keyLoader->loadDecryptionKeyPem();
        $jws = $this->jwe->decryptCompact($jwe, $privateKeyPem, $this->keyLoader->getDecryptionKeyPassphrase());

        $signingCertPem = $this->keyLoader->loadSigningCertPem();
        $payload = $this->jws->verifyCompact($jws, $signingCertPem);

        $data = json_decode($payload, true);
        if (!is_array($data)) {
            throw new \RuntimeException('Decrypted payload is not valid JSON.');
        }
        return new Person($data);
    }

    /**
     * One-shot verify-and-decrypt for raw JWE strings.
     * @return array<string,mixed>
     */
    public function verifyAndDecrypt(string $jwe): array
    {
        $privateKeyPem = $this->keyLoader->loadDecryptionKeyPem();
        $jws = $this->jwe->decryptCompact($jwe, $privateKeyPem, $this->keyLoader->getDecryptionKeyPassphrase());
        $signingCertPem = $this->keyLoader->loadSigningCertPem();
        $payload = $this->jws->verifyCompact($jws, $signingCertPem);
        $data = json_decode($payload, true);
        return is_array($data) ? $data : [];
    }

    /**
     * Returns the effective endpoints for inspection/debugging.
     * @return array<string,string>
     */
    public function getEndpoints(): array
    {
        return [
            'authorize' => $this->config->getAuthorizeUrl(),
            'token' => $this->config->getTokenUrl(),
            'person' => $this->config->getPersonUrl(),
        ];
    }
}
