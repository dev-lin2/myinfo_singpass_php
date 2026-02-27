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
use MyInfo\Crypto\JweService;
use MyInfo\Crypto\JwsService;
use MyInfo\Crypto\KeyLoader;
use MyInfo\DTO\AccessToken;
use MyInfo\DTO\Person;
use MyInfo\Exceptions\HttpException;
use MyInfo\Exceptions\OAuthException;
use MyInfo\Http\HttpClient;

class MyInfoClient
{
    private Config $config;
    private HttpClient $http;
    private KeyLoader $keyLoader;
    private JweService $jwe;
    private JwsService $jws;

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
        $this->keyLoader = new KeyLoader($config);
        $this->jwe = new JweService();
        $this->jws = new JwsService();
    }

    /** @param array<string,mixed> $overrides */
    public function buildAuthorizeUrl(array $overrides = []): string
    {
        return $this->config->isOidcMode()
            ? $this->buildOidcAuthorizeUrl($overrides)
            : $this->buildLegacyAuthorizeUrl($overrides);
    }

    /** @param array<string,mixed> $options */
    public function exchangeToken(string $code, ?string $redirectUri = null, array $options = []): AccessToken
    {
        if ($this->config->isOidcMode()) {
            return $this->exchangeOidcToken($code, $redirectUri, $options);
        }

        $res = $this->http->postForm($this->config->getTokenUrl(), [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri ?: $this->config->getRedirectUri(),
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

    /** @param array<string>|null $attributes */
    public function getPerson(string $accessToken, ?array $attributes = null, ?string $uinfin = null): Person
    {
        if ($this->config->isOidcMode()) {
            return $this->getOidcUserInfo($accessToken);
        }

        $attrs = $attributes ? implode(',', $attributes) : implode(',', $this->config->getAttributes());
        $headers = ['Authorization' => 'Bearer ' . $accessToken, 'Accept' => 'application/json'];

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
        $jwe = is_array($body) && isset($body['data']) ? (string) $body['data'] : trim((string) $res->getBody());
        if ($jwe === '') {
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

    /** @return array<string,mixed> */
    public function verifyAndDecrypt(string $input): array
    {
        if ($this->config->isOidcMode()) {
            return $this->decodeOidcPayload($input);
        }

        $privateKeyPem = $this->keyLoader->loadDecryptionKeyPem();
        $jws = $this->jwe->decryptCompact($input, $privateKeyPem, $this->keyLoader->getDecryptionKeyPassphrase());
        $signingCertPem = $this->keyLoader->loadSigningCertPem();
        $payload = $this->jws->verifyCompact($jws, $signingCertPem);
        $data = json_decode($payload, true);
        return is_array($data) ? $data : [];
    }

    /** @return array<string,string> */
    public function getEndpoints(): array
    {
        if ($this->config->isOidcMode()) {
            $m = $this->oidcMetadata();
            return [
                'authorize' => (string) ($m['authorization_endpoint'] ?? ''),
                'token' => (string) ($m['token_endpoint'] ?? ''),
                'person' => (string) ($m['userinfo_endpoint'] ?? ''),
            ];
        }
        return [
            'authorize' => $this->config->getAuthorizeUrl(),
            'token' => $this->config->getTokenUrl(),
            'person' => $this->config->getPersonUrl(),
        ];
    }

    /** @param array<string,mixed> $overrides */
    private function buildLegacyAuthorizeUrl(array $overrides): string
    {
        $attrs = $overrides['attributes'] ?? $this->config->getAttributes();
        if (is_string($attrs)) {
            $attrs = array_values(array_filter(array_map('trim', explode(',', $attrs))));
        }
        if (!is_array($attrs)) {
            $attrs = $this->config->getAttributes();
        }

        $params = [
            'client_id' => $this->config->getClientId(),
            'attributes' => implode(',', $attrs),
            'purpose' => $overrides['purpose'] ?? $this->config->getPurpose(),
            'redirect_uri' => $overrides['redirect_uri'] ?? $this->config->getRedirectUri(),
            'state' => $overrides['state'] ?? bin2hex(random_bytes(8)),
            'nonce' => $overrides['nonce'] ?? bin2hex(random_bytes(8)),
            'response_type' => 'code',
        ];
        return $this->config->getAuthorizeUrl() . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /** @param array<string,mixed> $overrides */
    private function buildOidcAuthorizeUrl(array $overrides): string
    {
        $m = $this->oidcMetadata();
        $o = $this->oidcSettings();

        $state = (string) ($overrides['state'] ?? $this->b64u(random_bytes(16)));
        $nonce = (string) ($overrides['nonce'] ?? $this->b64u(random_bytes(16)));
        $verifier = (string) ($overrides['code_verifier'] ?? $this->b64u(random_bytes(64)));
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

        if (!empty($m['pushed_authorization_request_endpoint']) && !empty($o['use_par'])) {
            $requestUri = $this->oidcPar((string) $m['pushed_authorization_request_endpoint'], $params);
            $params = ['client_id' => (string) $o['client_id'], 'request_uri' => $requestUri];
        }

        return (string) $m['authorization_endpoint'] . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /** @param array<string,mixed> $params */
    private function oidcPar(string $parEndpoint, array $params): string
    {
        $payload = array_merge($params, [
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $this->clientAssertion($parEndpoint),
        ]);
        $json = $this->oidcPost($parEndpoint, $payload, null);
        $uri = isset($json['request_uri']) ? (string) $json['request_uri'] : '';
        if ($uri === '') {
            throw new \RuntimeException('PAR response missing request_uri.');
        }
        return $uri;
    }

    /** @param array<string,mixed> $options */
    private function exchangeOidcToken(string $code, ?string $redirectUri, array $options): AccessToken
    {
        $m = $this->oidcMetadata();
        $o = $this->oidcSettings();
        $verifier = trim((string) ($options['code_verifier'] ?? ''));
        if ($verifier === '') {
            throw new OAuthException('OIDC code_verifier is required.');
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
        if (empty($body['access_token'])) {
            throw new OAuthException('Invalid OIDC token response.');
        }
        $expiresIn = isset($body['expires_in']) ? (int) $body['expires_in'] : 300;
        $expiresAt = CarbonImmutable::now()->addSeconds(max(1, $expiresIn));
        return new AccessToken((string) $body['access_token'], $expiresAt, $body['token_type'] ?? null, $body['scope'] ?? null);
    }

    private function getOidcUserInfo(string $accessToken): Person
    {
        $m = $this->oidcMetadata();
        $raw = $this->oidcGet((string) $m['userinfo_endpoint'], $accessToken);
        return new Person($this->decodeOidcPayload($raw));
    }

    /** @return array<string,mixed> */
    private function oidcPost(string $url, array $form, ?string $athToken): array
    {
        $nonce = null;
        for ($i = 0; $i < 2; $i++) {
            $headers = ['Accept' => 'application/json'];
            if (!empty($this->oidcSettings()['use_dpop'])) {
                $headers['DPoP'] = $this->dpopJwt('POST', $url, $athToken, $nonce);
            }
            try {
                $res = $this->http->postForm($url, $form, $headers);
                $json = json_decode((string) $res->getBody(), true);
                if (!is_array($json)) {
                    throw new \RuntimeException('OIDC endpoint returned non-JSON response.');
                }
                return $json;
            } catch (HttpException $e) {
                $resp = $e->getResponse();
                $next = $resp ? trim((string) $resp->getHeaderLine('DPoP-Nonce')) : '';
                if ($next !== '' && $nonce === null) {
                    $nonce = $next;
                    continue;
                }
                throw $e;
            }
        }
        throw new \RuntimeException('OIDC request failed.');
    }

    private function oidcGet(string $url, string $accessToken): string
    {
        $nonce = null;
        for ($i = 0; $i < 2; $i++) {
            $headers = ['Accept' => 'application/json', 'Authorization' => 'Bearer ' . $accessToken];
            if (!empty($this->oidcSettings()['use_dpop'])) {
                $headers['DPoP'] = $this->dpopJwt('GET', $url, $accessToken, $nonce);
            }
            try {
                $res = $this->http->get($url, [], $headers);
                return (string) $res->getBody();
            } catch (HttpException $e) {
                $resp = $e->getResponse();
                $next = $resp ? trim((string) $resp->getHeaderLine('DPoP-Nonce')) : '';
                if ($next !== '' && $nonce === null) {
                    $nonce = $next;
                    continue;
                }
                throw $e;
            }
        }
        throw new \RuntimeException('OIDC userinfo request failed.');
    }

    private function clientAssertion(string $aud): string
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
            'aud' => $aud,
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

    /** @param array<string,mixed> $header @param array<string,mixed> $claims @param array<string,mixed> $jwk */
    private function signJwt(array $header, array $claims, array $jwk): string
    {
        $alg = $this->sigAlg((string) ($header['alg'] ?? 'ES256'));
        $builder = new JWSBuilder(new AlgorithmManager([$alg]));
        $payload = json_encode($claims, JSON_UNESCAPED_SLASHES);
        if (!is_string($payload)) {
            throw new \RuntimeException('Unable to encode JWT payload.');
        }
        $jws = $builder->create()->withPayload($payload)->addSignature(new JWK($jwk), $header)->build();
        return (new JwsCompactSerializer())->serialize($jws, 0);
    }

    /** @return array<string,mixed> */
    private function decodeOidcPayload(string $raw): array
    {
        $raw = trim($raw);
        if ($raw === '') {
            throw new \RuntimeException('OIDC payload is empty.');
        }
        if ($raw[0] === '{' || $raw[0] === '[') {
            $d = json_decode($raw, true);
            if (is_array($d)) {
                return $d;
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
            throw new \RuntimeException('Unable to decrypt OIDC JWE payload.');
        }
        $payload = (string) $jwe->getPayload();
        if ($payload === '') {
            throw new \RuntimeException('OIDC JWE payload is empty.');
        }
        return $payload;
    }

    private function verifyOidcJws(string $token): string
    {
        $keys = $this->oidcJwks();
        $set = new JWKSet(array_map(static function (array $k) { return new JWK($k); }, $keys));
        $verifier = new JWSVerifier(new AlgorithmManager([new ES256(), new ES384(), new ES512()]));
        $loader = new JWSLoader(new JWSSerializerManager([new JwsCompactSerializer()]), $verifier, null);
        $sig = 0;
        $jws = $loader->loadAndVerifyWithKeySet($token, $set, $sig);
        $payload = (string) $jws->getPayload();
        if ($payload === '') {
            throw new \RuntimeException('OIDC JWS payload is empty.');
        }
        return $payload;
    }

    /** @return array<string,mixed> */
    private function oidcMetadata(): array
    {
        if ($this->oidcMeta !== null) {
            return $this->oidcMeta;
        }
        $issuer = rtrim((string) $this->oidcSettings()['issuer_url'], '/');
        $res = $this->http->get($issuer . '/.well-known/openid-configuration', [], ['Accept' => 'application/json']);
        $meta = json_decode((string) $res->getBody(), true);
        if (!is_array($meta)) {
            throw new \RuntimeException('OIDC discovery response is invalid.');
        }
        foreach (['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'] as $required) {
            if (empty($meta[$required])) {
                throw new \RuntimeException('OIDC discovery missing ' . $required . '.');
            }
        }
        $this->oidcMeta = $meta;
        return $this->oidcMeta;
    }

    /** @return array<int,array<string,mixed>> */
    private function oidcJwks(): array
    {
        if ($this->oidcJwks !== null) {
            return $this->oidcJwks;
        }
        $uri = (string) $this->oidcMetadata()['jwks_uri'];
        $res = $this->http->get($uri, [], ['Accept' => 'application/json']);
        $body = json_decode((string) $res->getBody(), true);
        $keys = is_array($body) && isset($body['keys']) && is_array($body['keys']) ? $body['keys'] : [];
        if (empty($keys)) {
            throw new \RuntimeException('OIDC JWKS response has no keys.');
        }
        $this->oidcJwks = array_values(array_filter($keys, static function ($k) { return is_array($k); }));
        return $this->oidcJwks;
    }

    /** @return array<string,mixed> */
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
                throw new \RuntimeException('MYINFO_OIDC_CONFIG_PATH file not found: ' . $resolved);
            }
            $decoded = json_decode((string) file_get_contents($resolved), true);
            if (!is_array($decoded)) {
                throw new \RuntimeException('MYINFO_OIDC_CONFIG_PATH must contain valid JSON object.');
            }
            $file = $decoded;
        }

        $keys = isset($file['KEYS']) && is_array($file['KEYS']) ? $file['KEYS'] : [];
        $this->oidc = [
            'client_id' => (string) ($cfg['client_id'] ?? ($file['CLIENT_ID'] ?? $this->config->getClientId())),
            'redirect_uri' => (string) ($cfg['redirect_uri'] ?? ($file['REDIRECT_URI'] ?? $this->config->getRedirectUri())),
            'issuer_url' => (string) ($cfg['issuer_url'] ?? ($file['ISSUER_URL'] ?? 'https://stg-id.singpass.gov.sg/fapi')),
            'scope' => trim((string) ($cfg['scope'] ?? ($file['SCOPES'] ?? 'openid uinfin name'))),
            'use_par' => $this->toBool($cfg['use_par'] ?? null, true),
            'use_dpop' => $this->toBool($cfg['use_dpop'] ?? null, true),
            'private_sig_jwk' => $this->readJwk($cfg['private_sig_jwk_json'] ?? null, $cfg['private_sig_jwk_path'] ?? null, $keys['PRIVATE_SIG_KEY'] ?? null),
            'public_sig_jwk' => $this->readJwk($cfg['public_sig_jwk_json'] ?? null, $cfg['public_sig_jwk_path'] ?? null, $keys['PUBLIC_SIG_KEY'] ?? null),
            'private_enc_jwk' => $this->readJwk($cfg['private_enc_jwk_json'] ?? null, $cfg['private_enc_jwk_path'] ?? null, $keys['PRIVATE_ENC_KEY'] ?? null),
        ];

        if ($this->oidc['client_id'] === '') {
            throw new \RuntimeException('OIDC client_id is missing.');
        }
        if ($this->oidc['redirect_uri'] === '') {
            throw new \RuntimeException('OIDC redirect_uri is missing.');
        }
        if ($this->oidc['scope'] === '') {
            throw new \RuntimeException('OIDC scope is missing.');
        }
        return $this->oidc;
    }

    /** @param mixed $json @param mixed $path @param mixed $fallback @return array<string,mixed>|null */
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
                throw new \RuntimeException('JWK file not found: ' . $resolved);
            }
            $d = json_decode((string) file_get_contents($resolved), true);
            if (!is_array($d)) {
                throw new \RuntimeException('Invalid JWK JSON in file: ' . $resolved);
            }
            return $d;
        }
        return is_array($fallback) ? $fallback : null;
    }

    /** @param mixed $v @return array<string,mixed> */
    private function needJwk($v, string $name): array
    {
        if (!is_array($v) || empty($v)) {
            throw new \RuntimeException($name . ' is required.');
        }
        return $v;
    }

    /** @param array<string,mixed> $sig @return array<string,mixed> */
    private function pubFromPrivate(array $sig): array
    {
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as $secret) {
            unset($sig[$secret]);
        }
        return $sig;
    }

    /** @param array<string,mixed> $pub @return array<string,mixed> */
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

    /** @return ES256|ES384|ES512 */
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

    /** @param mixed $value */
    private function toBool($value, bool $default): bool
    {
        if ($value === false || $value === true) {
            return (bool) $value;
        }
        if ($value === null) {
            return $default;
        }
        $v = strtolower(trim((string) $value));
        if ($v === '') {
            return $default;
        }
        if (in_array($v, ['1', 'true', 'yes', 'on'], true)) {
            return true;
        }
        if (in_array($v, ['0', 'false', 'no', 'off'], true)) {
            return false;
        }
        return $default;
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
