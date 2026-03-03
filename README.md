# MyInfo Singpass Package (FAPI 2.0 Only)

PHP package for Singpass / Myinfo v5 integration using OIDC + FAPI 2.0 profile.

## Installation

```composer require devlin/myinfo-singpass-laravel```

## Reference

- Official integration guide:
  https://docs.developer.singpass.gov.sg/docs/technical-specifications/integration-guide

## Scope

This package now supports only the modern FAPI 2.0 flow:

- Pushed Authorization Request (PAR)
- PKCE (`S256`)
- DPoP
- `private_key_jwt` client authentication
- Encrypted + signed `id_token` validation
- `/userinfo` retrieval with `Authorization: DPoP <access_token>`

Legacy MyInfo `/com/v3/*` flow is removed.

## Required Environment Variables

```dotenv
MYINFO_CLIENT_ID=...
MYINFO_REDIRECT_URI=http://localhost:8080/myinfo/callback
```

## Recommended Environment Variables

```dotenv
MYINFO_ISSUER_URL=https://stg-id.singpass.gov.sg/fapi
MYINFO_SCOPES=openid uinfin name
MYINFO_TIMEOUT_MS=10000
```

## Generating JWK Key Files

This package requires JWK key files for signing and encryption. If you don't have these yet, you can generate them using [`jwk-cli-tool`](https://www.npmjs.com/package/jwk-cli-tool) — an interactive CLI for generating PEM and JWK files.

```bash
npx jwk-cli-tool
```

The tool will guide you through:

1. **Generate PEM Key Pairs** — choose your algorithm (`ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512`) to produce `.pem` files
2. **Generate JWK JSON Files** — convert PEM keys to JWK format, set the key use (`sig` or `enc`), and assign a key ID

Run it twice — once for your **signing key** (`sig`) and once for your **encryption key** (`enc`) — then reference the output files in the env vars below.

> Requires Node.js 18+.

## Key Configuration (choose one)

### Option A: Singpass config JSON (recommended)

```dotenv
MYINFO_OIDC_CONFIG_PATH=./config/singpass-config.json
```

Expected JSON fields are `CLIENT_ID`, `REDIRECT_URI`, `ISSUER_URL`, and `KEYS`.

### Option B: explicit JWK env values

```dotenv
MYINFO_OIDC_PRIVATE_SIG_JWK_PATH=./myinfo/private_sig.jwk.json
MYINFO_OIDC_PUBLIC_SIG_JWK_PATH=./myinfo/public_sig.jwk.json
MYINFO_OIDC_PRIVATE_ENC_JWK_PATH=./myinfo/private_enc.jwk.json
```

## Optional Reliability Settings

```dotenv
MYINFO_OIDC_RETRY_ATTEMPTS=3
MYINFO_OIDC_RETRY_BACKOFF_MS=250
MYINFO_OIDC_CLIENT_ASSERTION_AUDIENCE=
```

`MYINFO_OIDC_CLIENT_ASSERTION_AUDIENCE` is optional. If empty, the package uses OIDC discovery issuer.

## Optional Signature Verification Key Override

By default, the package verifies ID token and UserInfo signatures using the issuer discovery `jwks_uri`.

If you want to pin verification keys locally, set either:

```dotenv
MYINFO_OIDC_VERIFICATION_JWKS_PATH=./myinfo/myinfo_pub.jwk.json
```

or

```dotenv
MYINFO_OIDC_VERIFICATION_JWKS_JSON={...}
```

Accepted formats:

- JWKS object: `{ "keys": [ ... ] }`
- single JWK object
- array of JWK objects

## Minimal Usage

```php
use Illuminate\Support\Str;
use MyInfo\Laravel\Facades\MyInfo;

// Redirect step
$state = Str::random(32);
$nonce = Str::random(32);
$codeVerifier = rtrim(strtr(base64_encode(random_bytes(64)), '+/', '-_'), '=');

session([
    'myinfo_state_'.$state => [
        'code_verifier' => $codeVerifier,
        'nonce' => $nonce,
    ],
]);

$url = MyInfo::buildAuthorizeUrl([
    'state' => $state,
    'nonce' => $nonce,
    'code_verifier' => $codeVerifier,
]);

return redirect()->away($url);
```

```php
use MyInfo\Laravel\Facades\MyInfo;

// Callback step
$code = (string) request('code', '');
$state = (string) request('state', '');
$ctx = (array) session('myinfo_state_'.$state, []);
session()->forget('myinfo_state_'.$state);

$token = MyInfo::exchangeToken($code, null, [
    'code_verifier' => (string) ($ctx['code_verifier'] ?? ''),
    'nonce' => (string) ($ctx['nonce'] ?? ''),
]);

// id_token claims are already verified (iss, aud, exp, nonce)
$idTokenClaims = $token->getIdTokenClaims();

// Fetch Myinfo user data from /userinfo
$person = MyInfo::getPerson($token->getValue())->toArray();
```

## Runtime Behavior

- PAR is always used.
- DPoP is always used for PAR, token, and userinfo calls.
- `token_type` must be `DPoP`.
- `openid` must be present in requested scopes.
- `id_token` claims are validated: `iss`, `aud`, `exp`, `nonce`.
