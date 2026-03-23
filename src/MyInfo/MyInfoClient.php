<?php

namespace MyInfo;

use Carbon\CarbonImmutable;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer as JweCompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as JwsCompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use MyInfo\DTO\AccessToken;
use MyInfo\DTO\Person;
use MyInfo\Exceptions\HttpException;
use MyInfo\Exceptions\OAuthException;
use MyInfo\Http\HttpClient;

/**
 * Singpass / Myinfo v5 client using OIDC + FAPI 2.0 controls.
 */
class MyInfoClient
{
    private Config $config;
    private HttpClient $http;

    /** @var array<string,mixed>|null */
    private ?array $oidc = null;
    /** @var array<string,mixed>|null */
    private ?array $oidcMeta = null;
    /** @var array<int,array<string,mixed>>|null */
    private ?array $oidcJwks = null;

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->http = new HttpClient($config->getTimeoutMs());
    }

    /**
     * Build authorization URL using PAR (mandatory in FAPI 2.0 profile).
     * @param array<string,mixed> $overrides
     */
    public function buildAuthorizeUrl(array $overrides = []): string
    {
        return $this->buildOidcAuthorizeUrl($overrides);
    }

    /**
     * Exchange authorization code for tokens and validate id_token claims.
     * @param array<string,mixed> $options
     */
    public function exchangeToken(string $code, ?string $redirectUri = null, array $options = []): AccessToken
    {
        return $this->exchangeOidcToken($code, $redirectUri, $options);
    }

    /**
     * Retrieve user information from the OIDC userinfo endpoint.
     *
     * Note: $attributes and $uinfin are ignored in FAPI v5 flow and kept only
     * for backward method compatibility in existing call sites.
     *
     * @param array<string>|null $attributes
     */
    public function getPerson(string $accessToken, ?array $attributes = null, ?string $uinfin = null): Person
    {
        unset($attributes, $uinfin);
        return $this->getOidcUserInfo($accessToken);
    }

    /**
     * Decrypts/verifies OIDC id_token and validates core claims.
     * @return array<string,mixed>
     */
    public function verifyIdToken(string $idToken, ?string $expectedNonce = null): array
    {
        $claims = $this->decodeOidcPayload($idToken);
        $this->verifyIdTokenClaims($claims, $expectedNonce);
        return $claims;
    }

    /**
     * Generic helper for decrypting/verifying signed+encrypted payloads.
     * @return array<string,mixed>
     */
    public function verifyAndDecrypt(string $input): array
    {
        return $this->decodeOidcPayload($input);
    }

    /** @return array<string,string> */
    public function getEndpoints(): array
    {
        $m = $this->oidcMetadata();
        return [
            'authorize' => (string) ($m['authorization_endpoint'] ?? ''),
            'token' => (string) ($m['token_endpoint'] ?? ''),
            'person' => (string) ($m['userinfo_endpoint'] ?? ''),
            'par' => (string) ($m['pushed_authorization_request_endpoint'] ?? ''),
        ];
    }

    /**
     * @param array<string,mixed> $overrides
     */
    private function buildOidcAuthorizeUrl(array $overrides): string
    {
        $m = $this->oidcMetadata();
        $o = $this->oidcSettings();

        $state = (string) ($overrides['state'] ?? $this->b64u(random_bytes(16)));
        $nonce = (string) ($overrides['nonce'] ?? $this->b64u(random_bytes(16)));
        $verifier = (string) ($overrides['code_verifier'] ?? $this->b64u(random_bytes(64)));
        $this->assertCodeVerifier($verifier);
        $challenge = (string) ($overrides['code_challenge'] ?? $this->b64u(hash('sha256', $verifier, true)));

        $params = [
            'response_type' => 'code',
            'client_id' => (string) $o['client_id'],
            'redirect_uri' => (string) ($overrides['redirect_uri'] ?? $o['redirect_uri']),
            'scope' => (string) ($overrides['scope'] ?? $o['scope']),
            'code_challenge_method' => 'S256',
            'code_challenge' => $challenge,
            'state' => $state,
            'nonce' => $nonce,
        ];

        $requestUri = $this->oidcPar((string) $m['pushed_authorization_request_endpoint'], $params);
        $final = [
            'client_id' => (string) $o['client_id'],
            'request_uri' => $requestUri,
        ];

        return (string) $m['authorization_endpoint'] . '?' . http_build_query($final, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @param array<string,mixed> $params
     */
    private function oidcPar(string $parEndpoint, array $params): string
    {
        $payload = array_merge($params, [
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion($parEndpoint),
        ]);

        $json = $this->oidcPost($parEndpoint, $payload, null);
        $uri = isset($json['request_uri']) ? (string) $json['request_uri'] : '';
        if ($uri === '') {
            throw new OAuthException('PAR response missing request_uri.');
        }

        return $uri;
    }

    /**
     * @param array<string,mixed> $options
     */
    private function exchangeOidcToken(string $code, ?string $redirectUri, array $options): AccessToken
    {
        $m = $this->oidcMetadata();
        $o = $this->oidcSettings();

        $verifier = trim((string) ($options['code_verifier'] ?? ''));
        if ($verifier === '') {
            throw new OAuthException('OIDC code_verifier is required.');
        }
        $this->assertCodeVerifier($verifier);

        $nonce = trim((string) ($options['nonce'] ?? ''));
        if ($nonce === '') {
            throw new OAuthException('OIDC nonce is required for id_token verification.');
        }

        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri ?: (string) $o['redirect_uri'],
            'client_id' => (string) $o['client_id'],
            'code_verifier' => $verifier,
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion((string) $m['token_endpoint']),
        ];

        $body = $this->oidcPost((string) $m['token_endpoint'], $form, null);

        $accessToken = isset($body['access_token']) ? trim((string) $body['access_token']) : '';
        if ($accessToken === '') {
            throw new OAuthException('Token response missing access_token.');
        }

        $idToken = isset($body['id_token']) ? trim((string) $body['id_token']) : '';
        if ($idToken === '') {
            throw new OAuthException('Token response missing id_token.');
        }

        $tokenType = isset($body['token_type']) ? trim((string) $body['token_type']) : '';
        if (strtoupper($tokenType) !== 'DPOP') {
            throw new OAuthException('Token response token_type must be DPoP.');
        }

        $idTokenClaims = $this->verifyIdToken($idToken, $nonce);
        $expiresIn = isset($body['expires_in']) ? (int) $body['expires_in'] : 300;
        $expiresAt = CarbonImmutable::now()->addSeconds(max(1, $expiresIn));

        return new AccessToken(
            $accessToken,
            $expiresAt,
            $tokenType,
            isset($body['scope']) ? (string) $body['scope'] : null,
            $idToken,
            $idTokenClaims
        );
    }

    private function getOidcUserInfo(string $accessToken): Person
    {
        $m = $this->oidcMetadata();
        $raw = $this->oidcGet((string) $m['userinfo_endpoint'], $accessToken);
        return new Person($this->decodeOidcPayload($raw));
    }

    /**
     * @param array<string,mixed> $form
     * @return array<string,mixed>
     */
    private function oidcPost(string $url, array $form, ?string $athToken): array
    {
        $nonce = null;
        $attempts = max(1, $this->retryAttemptLimit());

        for ($i = 0; $i < $attempts; $i++) {
            $headers = [
                'Accept' => 'application/json',
                'DPoP' => $this->dpopJwt('POST', $url, $athToken, $nonce),
            ];

            try {
                $res = $this->http->postForm($url, $form, $headers);
                $json = json_decode((string) $res->getBody(), true);
                if (!is_array($json)) {
                    throw new OAuthException('OIDC endpoint returned non-JSON response.');
                }
                return $json;
            } catch (HttpException $e) {
                $resp = $e->getResponse();
                $next = $resp ? trim((string) $resp->getHeaderLine('DPoP-Nonce')) : '';
                if ($next !== '' && $next !== $nonce) {
                    $nonce = $next;
                    continue;
                }
                if ($i + 1 < $attempts && $this->isRetryableOidcError($e)) {
                    $this->sleepBeforeRetry($i + 1);
                    continue;
                }
                throw $e;
            }
        }

        throw new OAuthException('OIDC request failed after retries.');
    }

    private function oidcGet(string $url, string $accessToken): string
    {
        $nonce = null;
        $attempts = max(1, $this->retryAttemptLimit());

        for ($i = 0; $i < $attempts; $i++) {
            $headers = [
                'Accept' => 'application/json',
                'Authorization' => 'DPoP ' . $accessToken,
                'DPoP' => $this->dpopJwt('GET', $url, $accessToken, $nonce),
            ];

            try {
                $res = $this->http->get($url, [], $headers);
                return (string) $res->getBody();
            } catch (HttpException $e) {
                $resp = $e->getResponse();
                $next = $resp ? trim((string) $resp->getHeaderLine('DPoP-Nonce')) : '';
                if ($next !== '' && $next !== $nonce) {
                    $nonce = $next;
                    continue;
                }
                if ($i + 1 < $attempts && $this->isRetryableOidcError($e)) {
                    $this->sleepBeforeRetry($i + 1);
                    continue;
                }
                throw $e;
            }
        }

        throw new OAuthException('OIDC userinfo request failed after retries.');
    }

    private function clientAssertion(string $endpoint): string
    {
        $o = $this->oidcSettings();
        $sig = $this->needJwk($o['private_sig_jwk'] ?? null, 'OIDC private signing key');
        $alg = strtoupper((string) ($sig['alg'] ?? 'ES256'));
        $now = time();

        $header = ['alg' => $alg, 'typ' => 'JWT'];
        if (!empty($sig['kid'])) {
            $header['kid'] = (string) $sig['kid'];
        }

        $claims = [
            'iss' => (string) $o['client_id'],
            'sub' => (string) $o['client_id'],
            'aud' => $this->resolveClientAssertionAudience($endpoint),
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => $this->b64u(random_bytes(16)),
        ];

        return $this->signJwt($header, $claims, $sig);
    }

    private function dpopJwt(string $method, string $url, ?string $athToken, ?string $nonce): string
    {
        $o = $this->oidcSettings();
        $sig = $this->needJwk($o['private_sig_jwk'] ?? null, 'OIDC private signing key');
        $pub = is_array($o['public_sig_jwk'] ?? null) ? $o['public_sig_jwk'] : $this->pubFromPrivate($sig);
        $alg = strtoupper((string) ($sig['alg'] ?? 'ES256'));

        $header = ['typ' => 'dpop+jwt', 'alg' => $alg, 'jwk' => $this->sanitizePub($pub)];
        if (!empty($sig['kid'])) {
            $header['kid'] = (string) $sig['kid'];
        }

        $claims = [
            'htm' => strtoupper($method),
            'htu' => $this->htu($url),
            'iat' => time(),
            'exp' => time() + 120,
            'jti' => $this->b64u(random_bytes(16)),
        ];

        if ($athToken !== null && $athToken !== '') {
            $claims['ath'] = $this->b64u(hash('sha256', $athToken, true));
        }
        if ($nonce !== null && $nonce !== '') {
            $claims['nonce'] = $nonce;
        }

        return $this->signJwt($header, $claims, $sig);
    }

    /**
     * @param array<string,mixed> $header
     * @param array<string,mixed> $claims
     * @param array<string,mixed> $jwk
     */
    private function signJwt(array $header, array $claims, array $jwk): string
    {
        $alg = $this->sigAlg((string) ($header['alg'] ?? 'ES256'));
        $builder = new JWSBuilder(new AlgorithmManager([$alg]));

        $payload = json_encode($claims, JSON_UNESCAPED_SLASHES);
        if (!is_string($payload)) {
            throw new OAuthException('Unable to encode JWT payload.');
        }

        $jws = $builder->create()->withPayload($payload)->addSignature(new JWK($jwk), $header)->build();
        return (new JwsCompactSerializer())->serialize($jws, 0);
    }

    /**
     * @return array<string,mixed>
     */
    private function decodeOidcPayload(string $raw): array
    {
        $raw = trim($raw);
        if ($raw === '') {
            throw new OAuthException('OIDC payload is empty.');
        }

        if ($raw[0] === '{' || $raw[0] === '[') {
            $json = json_decode($raw, true);
            if (is_array($json)) {
                return $json;
            }
        }

        if (substr_count($raw, '.') === 4) {
            return $this->decodeOidcPayload($this->decryptOidcJwe($raw));
        }

        if (substr_count($raw, '.') === 2) {
            return $this->decodeOidcPayload($this->verifyOidcJws($raw));
        }

        return ['raw' => $raw];
    }

    private function decryptOidcJwe(string $token): string
    {
        $enc = $this->needJwk($this->oidcSettings()['private_enc_jwk'] ?? null, 'OIDC private encryption key');

        $decrypter = new JWEDecrypter(
            new AlgorithmManager([new ECDHESA128KW(), new ECDHESA192KW(), new ECDHESA256KW()]),
            new AlgorithmManager([new A256GCM(), new A256CBCHS512()]),
            new CompressionMethodManager([])
        );

        $loader = new JWELoader(new JWESerializerManager([new JweCompactSerializer()]), $decrypter, null);
        $idx = 0;
        $jwe = $loader->loadAndDecryptWithKey($token, new JWK($enc), $idx);
        if (!$jwe) {
            throw new OAuthException('Unable to decrypt OIDC JWE payload.');
        }

        $payload = (string) $jwe->getPayload();
        if ($payload === '') {
            throw new OAuthException('OIDC JWE payload is empty.');
        }

        return $payload;
    }

    private function verifyOidcJws(string $token): string
    {
        $keys = $this->oidcJwks();
        $set = new JWKSet(array_map(static function (array $k) {
            return new JWK($k);
        }, $keys));

        $verifier = new JWSVerifier(new AlgorithmManager([new ES256(), new ES384(), new ES512()]));
        $loader = new JWSLoader(new JWSSerializerManager([new JwsCompactSerializer()]), $verifier, null);
        $sig = 0;
        $jws = $loader->loadAndVerifyWithKeySet($token, $set, $sig);

        $payload = (string) $jws->getPayload();
        if ($payload === '') {
            throw new OAuthException('OIDC JWS payload is empty.');
        }

        return $payload;
    }

    /**
     * @return array<string,mixed>
     */
    private function oidcMetadata(): array
    {
        if ($this->oidcMeta !== null) {
            return $this->oidcMeta;
        }

        $issuer = rtrim((string) $this->oidcSettings()['issuer_url'], '/');
        $res = $this->http->get($issuer . '/.well-known/openid-configuration', [], ['Accept' => 'application/json']);
        $meta = json_decode((string) $res->getBody(), true);
        if (!is_array($meta)) {
            throw new OAuthException('OIDC discovery response is invalid.');
        }

        foreach ([
            'issuer',
            'authorization_endpoint',
            'token_endpoint',
            'userinfo_endpoint',
            'jwks_uri',
            'pushed_authorization_request_endpoint',
        ] as $required) {
            if (empty($meta[$required])) {
                throw new OAuthException('OIDC discovery missing ' . $required . '.');
            }
        }

        $this->oidcMeta = $meta;
        return $this->oidcMeta;
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function oidcJwks(): array
    {
        if ($this->oidcJwks !== null) {
            return $this->oidcJwks;
        }

        $local = $this->oidcSettings()['verification_jwks'] ?? null;
        if (is_array($local) && !empty($local)) {
            $this->oidcJwks = array_values(array_filter($local, static function ($k) {
                return is_array($k) && !empty($k);
            }));
            if (!empty($this->oidcJwks)) {
                return $this->oidcJwks;
            }
        }

        $uri = (string) $this->oidcMetadata()['jwks_uri'];
        $res = $this->http->get($uri, [], ['Accept' => 'application/json']);
        $body = json_decode((string) $res->getBody(), true);
        $keys = is_array($body) && isset($body['keys']) && is_array($body['keys']) ? $body['keys'] : [];
        if (empty($keys)) {
            throw new OAuthException('OIDC JWKS response has no keys.');
        }

        $this->oidcJwks = array_values(array_filter($keys, static function ($k) {
            return is_array($k);
        }));
        return $this->oidcJwks;
    }

    /**
     * @return array<string,mixed>
     */
    private function oidcSettings(): array
    {
        if ($this->oidc !== null) {
            return $this->oidc;
        }

        $cfg = $this->config->getOidc();
        if (!is_array($cfg)) {
            $cfg = [];
        }

        $file = [];
        $configPath = trim((string) ($cfg['config_path'] ?? ''));
        if ($configPath !== '') {
            $resolved = $this->resolvePath($configPath);
            if (!is_file($resolved)) {
                throw new OAuthException('MYINFO_OIDC_CONFIG_PATH file not found: ' . $resolved);
            }
            $decoded = json_decode((string) file_get_contents($resolved), true);
            if (!is_array($decoded)) {
                throw new OAuthException('MYINFO_OIDC_CONFIG_PATH must contain valid JSON object.');
            }
            $file = $decoded;
        }

        $keys = isset($file['KEYS']) && is_array($file['KEYS']) ? $file['KEYS'] : [];
        $this->oidc = [
            'client_id' => (string) ($cfg['client_id'] ?? ($file['CLIENT_ID'] ?? $this->config->getClientId())),
            'redirect_uri' => (string) ($cfg['redirect_uri'] ?? ($file['REDIRECT_URI'] ?? $this->config->getRedirectUri())),
            'issuer_url' => (string) ($cfg['issuer_url'] ?? ($file['ISSUER_URL'] ?? 'https://stg-id.singpass.gov.sg/fapi')),
            'scope' => trim((string) ($cfg['scope'] ?? ($file['SCOPES'] ?? 'openid uinfin name'))),
            'client_assertion_audience' => trim((string) ($cfg['client_assertion_audience'] ?? ($file['CLIENT_ASSERTION_AUDIENCE'] ?? ''))),
            'retry_attempts' => max(1, (int) ($cfg['retry_attempts'] ?? 3)),
            'retry_backoff_ms' => max(50, (int) ($cfg['retry_backoff_ms'] ?? 250)),
            'private_sig_jwk' => $this->readJwk(
                $cfg['private_sig_jwk_json'] ?? null,
                $cfg['private_sig_jwk_path'] ?? null,
                $keys['PRIVATE_SIG_KEY'] ?? null
            ),
            'public_sig_jwk' => $this->readJwk(
                $cfg['public_sig_jwk_json'] ?? null,
                $cfg['public_sig_jwk_path'] ?? null,
                $keys['PUBLIC_SIG_KEY'] ?? null
            ),
            'private_enc_jwk' => $this->readJwk(
                $cfg['private_enc_jwk_json'] ?? null,
                $cfg['private_enc_jwk_path'] ?? null,
                $keys['PRIVATE_ENC_KEY'] ?? null
            ),
            'verification_jwks' => $this->readJwkSet(
                $cfg['verification_jwks_json'] ?? null,
                $cfg['verification_jwks_path'] ?? null
            ),
        ];

        if ($this->oidc['client_id'] === '') {
            throw new OAuthException('OIDC client_id is missing.');
        }
        if ($this->oidc['redirect_uri'] === '') {
            throw new OAuthException('OIDC redirect_uri is missing.');
        }
        if ($this->oidc['scope'] === '') {
            throw new OAuthException('OIDC scope is missing.');
        }
        if (!$this->scopeContainsOpenId((string) $this->oidc['scope'])) {
            throw new OAuthException('OIDC scope must include openid.');
        }

        $this->needJwk($this->oidc['private_sig_jwk'] ?? null, 'OIDC private signing key');
        $this->needJwk($this->oidc['private_enc_jwk'] ?? null, 'OIDC private encryption key');

        return $this->oidc;
    }

    /**
     * @param mixed $json
     * @param mixed $path
     * @param mixed $fallback
     * @return array<string,mixed>|null
     */
    private function readJwk($json, $path, $fallback): ?array
    {
        if (is_array($json)) {
            return $json;
        }

        if (is_string($json) && trim($json) !== '') {
            $d = json_decode(trim($json), true);
            if (is_array($d)) {
                return $d;
            }
        }

        if (is_string($path) && trim($path) !== '') {
            $resolved = $this->resolvePath(trim($path));
            if (!is_file($resolved)) {
                throw new OAuthException('JWK file not found: ' . $resolved);
            }
            $d = json_decode((string) file_get_contents($resolved), true);
            if (!is_array($d)) {
                throw new OAuthException('Invalid JWK JSON in file: ' . $resolved);
            }
            return $d;
        }

        return is_array($fallback) ? $fallback : null;
    }

    /**
     * Reads verification keys from JSON string or file.
     * Accepts JWKS ({ "keys": [...] }), list of JWK objects, or single JWK object.
     *
     * @param mixed $json
     * @param mixed $path
     * @return array<int,array<string,mixed>>|null
     */
    private function readJwkSet($json, $path): ?array
    {
        $decoded = null;

        if (is_string($json) && trim($json) !== '') {
            $decoded = json_decode(trim($json), true);
            if (!is_array($decoded)) {
                throw new OAuthException('Invalid JWKS JSON in MYINFO_OIDC_VERIFICATION_JWKS_JSON.');
            }
        }

        if ($decoded === null && is_string($path) && trim($path) !== '') {
            $resolved = $this->resolvePath(trim($path));
            if (!is_file($resolved)) {
                throw new OAuthException('Verification JWKS file not found: ' . $resolved);
            }
            $decoded = json_decode((string) file_get_contents($resolved), true);
            if (!is_array($decoded)) {
                throw new OAuthException('Invalid JWKS JSON in file: ' . $resolved);
            }
        }

        if ($decoded === null) {
            return null;
        }

        $keys = [];
        if (isset($decoded['keys']) && is_array($decoded['keys'])) {
            $keys = $decoded['keys'];
        } elseif ($this->isSequentialArray($decoded)) {
            $keys = $decoded;
        } else {
            $keys = [$decoded];
        }

        $keys = array_values(array_filter($keys, static function ($k) {
            return is_array($k) && !empty($k);
        }));

        if (empty($keys)) {
            throw new OAuthException('Verification JWKS is empty.');
        }

        return $keys;
    }

    /**
     * @param mixed $v
     * @return array<string,mixed>
     */
    private function needJwk($v, string $name): array
    {
        if (!is_array($v) || empty($v)) {
            throw new OAuthException($name . ' is required.');
        }
        return $v;
    }

    /**
     * @param array<string,mixed> $sig
     * @return array<string,mixed>
     */
    private function pubFromPrivate(array $sig): array
    {
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as $secret) {
            unset($sig[$secret]);
        }
        return $sig;
    }

    /**
     * @param array<string,mixed> $pub
     * @return array<string,mixed>
     */
    private function sanitizePub(array $pub): array
    {
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as $secret) {
            unset($pub[$secret]);
        }
        return $pub;
    }

    private function htu(string $url): string
    {
        $p = parse_url($url);
        if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) {
            return $url;
        }

        $scheme = strtolower((string) $p['scheme']);
        $host = strtolower((string) $p['host']);
        $port = isset($p['port']) ? (int) $p['port'] : null;
        $path = isset($p['path']) && $p['path'] !== '' ? (string) $p['path'] : '/';
        $default = ($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80);

        return $scheme . '://' . $host . (($port !== null && !$default) ? ':' . $port : '') . $path;
    }

    private function b64u(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    private function assertCodeVerifier(string $verifier): void
    {
        if (!preg_match('/^[A-Za-z0-9\-_]{43,128}$/', $verifier)) {
            throw new OAuthException('OIDC code_verifier is invalid. Use base64url characters with length 43-128.');
        }
    }

    /**
     * @param array<string,mixed> $claims
     */
    private function verifyIdTokenClaims(array $claims, ?string $expectedNonce): void
    {
        $meta = $this->oidcMetadata();
        $o = $this->oidcSettings();

        $expectedIss = $this->normalizeIssuer((string) ($meta['issuer'] ?? $o['issuer_url']));
        $actualIss = $this->normalizeIssuer((string) ($claims['iss'] ?? ''));
        if ($actualIss === '' || !hash_equals($expectedIss, $actualIss)) {
            throw new OAuthException('OIDC id_token issuer mismatch.');
        }

        $clientId = (string) $o['client_id'];
        $aud = $claims['aud'] ?? null;
        $audOk = false;
        if (is_string($aud)) {
            $audOk = hash_equals($clientId, $aud);
        } elseif (is_array($aud)) {
            foreach ($aud as $v) {
                if (is_string($v) && hash_equals($clientId, $v)) {
                    $audOk = true;
                    break;
                }
            }
        }
        if (!$audOk) {
            throw new OAuthException('OIDC id_token audience mismatch.');
        }

        $exp = isset($claims['exp']) ? (int) $claims['exp'] : 0;
        if ($exp <= 0) {
            throw new OAuthException('OIDC id_token exp claim is missing.');
        }
        if (time() >= $exp) {
            throw new OAuthException('OIDC id_token has expired.');
        }

        $nonce = trim((string) ($claims['nonce'] ?? ''));
        if ($nonce === '' || !hash_equals($expectedNonce ?: '', $nonce)) {
            throw new OAuthException('OIDC id_token nonce mismatch.');
        }
    }

    private function normalizeIssuer(string $issuer): string
    {
        return rtrim(trim($issuer), '/');
    }

    private function scopeContainsOpenId(string $scope): bool
    {
        $parts = preg_split('/\s+/', trim($scope)) ?: [];
        foreach ($parts as $part) {
            if (is_string($part) && strtolower($part) === 'openid') {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array<mixed> $value
     */
    private function isSequentialArray(array $value): bool
    {
        $i = 0;
        foreach (array_keys($value) as $key) {
            if ($key !== $i) {
                return false;
            }
            $i++;
        }
        return true;
    }

    private function resolveClientAssertionAudience(string $endpoint): string
    {
        $o = $this->oidcSettings();
        $explicit = trim((string) ($o['client_assertion_audience'] ?? ''));
        if ($explicit !== '') {
            return $explicit;
        }

        $issuer = $this->normalizeIssuer((string) ($this->oidcMetadata()['issuer'] ?? ''));
        if ($issuer !== '') {
            return $issuer;
        }

        $configuredIssuer = $this->normalizeIssuer((string) ($o['issuer_url'] ?? ''));
        if ($configuredIssuer !== '') {
            return $configuredIssuer;
        }

        return $endpoint;
    }

    private function retryAttemptLimit(): int
    {
        return (int) ($this->oidcSettings()['retry_attempts'] ?? 3);
    }

    private function retryBackoffMicros(int $attempt): int
    {
        $baseMs = (int) ($this->oidcSettings()['retry_backoff_ms'] ?? 250);
        $step = max(0, $attempt - 1);
        $delayMs = $baseMs * (int) pow(2, $step);
        return max(50, $delayMs) * 1000;
    }

    private function sleepBeforeRetry(int $attempt): void
    {
        usleep($this->retryBackoffMicros($attempt));
    }

    private function isRetryableOidcError(HttpException $e): bool
    {
        $resp = $e->getResponse();
        if ($resp === null) {
            return false;
        }

        $status = $resp->getStatusCode();
        if ($status >= 500) {
            return true;
        }

        $err = $this->oauthErrorCodeFromException($e);
        return in_array(
            $err,
            ['server_error', 'temporarily_unavailable', 'upstream_dependency_error', 'upstream_depedency_error'],
            true
        );
    }

    private function oauthErrorCodeFromException(HttpException $e): ?string
    {
        $resp = $e->getResponse();
        if ($resp === null) {
            return null;
        }

        $body = trim((string) $resp->getBody());
        if ($body !== '') {
            $json = json_decode($body, true);
            if (is_array($json) && isset($json['error']) && is_string($json['error'])) {
                return trim($json['error']);
            }
        }

        $wwwAuth = trim((string) $resp->getHeaderLine('WWW-Authenticate'));
        if ($wwwAuth !== '' && preg_match('/error=\"([^\"]+)\"/i', $wwwAuth, $m) === 1) {
            return trim((string) ($m[1] ?? ''));
        }

        return null;
    }

    /**
     * @return ES256|ES384|ES512
     */
    private function sigAlg(string $alg)
    {
        switch (strtoupper(trim($alg))) {
            case 'ES512':
                return new ES512();
            case 'ES384':
                return new ES384();
            case 'ES256':
            default:
                return new ES256();
        }
    }

    private function resolvePath(string $path): string
    {
        if ($path === '') {
            return $path;
        }
        if (preg_match('/^[A-Za-z]:\\\\/', $path) === 1 || strpos($path, '/') === 0) {
            return $path;
        }
        if (function_exists('base_path')) {
            try {
                return (string) base_path($path);
            } catch (\Throwable $e) {
            }
        }
        return getcwd() . DIRECTORY_SEPARATOR . $path;
    }
}
