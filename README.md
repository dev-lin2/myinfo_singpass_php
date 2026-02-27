# MyInfo Singpass Package

Simple Laravel package for Singpass/MyInfo integration.

## Modes

- `legacy`: old MyInfo `/com/v3/*` flow
- `oidc_fapi` (or `oidc`/`fapi`): OIDC/FAPI flow (recommended from 2026 onward)

Set mode:

```dotenv
MYINFO_MODE=oidc_fapi
```

## OIDC/FAPI Quick Setup (Recommended)

### Required `.env`

```dotenv
MYINFO_MODE=oidc_fapi
MYINFO_CLIENT_ID=...
MYINFO_REDIRECT_URI=http://localhost:8080/myinfo/callback
MYINFO_ISSUER_URL=https://stg-id.singpass.gov.sg/fapi
MYINFO_SCOPES=openid uinfin name

# easiest: point to Singpass demo config.json (contains KEYS block)
MYINFO_OIDC_CONFIG_PATH=./config/singpass-config.json
```

### Optional `.env`

```dotenv
# defaults are true
MYINFO_OIDC_USE_PAR=true
MYINFO_OIDC_USE_DPOP=true

# use these only if not using MYINFO_OIDC_CONFIG_PATH
MYINFO_OIDC_PRIVATE_SIG_JWK_JSON=
MYINFO_OIDC_PUBLIC_SIG_JWK_JSON=
MYINFO_OIDC_PRIVATE_ENC_JWK_JSON=

# or JWK file paths
MYINFO_OIDC_PRIVATE_SIG_JWK_PATH=
MYINFO_OIDC_PUBLIC_SIG_JWK_PATH=
MYINFO_OIDC_PRIVATE_ENC_JWK_PATH=
```

Notes:

- OIDC/FAPI uses `private_key_jwt` + PKCE + DPoP.
- `MYINFO_CLIENT_SECRET` is not required in OIDC/FAPI mode.

## Legacy Mode Quick Setup

Use this only for older integrations.

```dotenv
MYINFO_MODE=legacy
MYINFO_ENV=sandbox
MYINFO_CLIENT_ID=...
MYINFO_CLIENT_SECRET=...
MYINFO_REDIRECT_URI=http://localhost:8080/myinfo/callback
MYINFO_SIGNING_CERT_PATH=./ssl/staging_myinfo_public_cert.cer
MYINFO_DECRYPTION_KEY_PATH=./ssl/your_app_private_key.pem
```

Optional legacy endpoint overrides:

```dotenv
MYINFO_BASE_URL_AUTH=https://sandbox.api.myinfo.gov.sg/com/v3/authorise
MYINFO_TOKEN_URL=https://sandbox.api.myinfo.gov.sg/com/v3/token
MYINFO_BASE_URL_API=https://sandbox.api.myinfo.gov.sg/com/v3/person
```

## Minimal Usage

```php
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use MyInfo\Laravel\Facades\MyInfo;

// redirect
$state = Str::random(32);
$nonce = Str::random(32);
$codeVerifier = rtrim(strtr(base64_encode(random_bytes(64)), '+/', '-_'), '=');
session(['myinfo_state_'.$state => $codeVerifier]);

$url = MyInfo::buildAuthorizeUrl([
    'state' => $state,
    'nonce' => $nonce,
    'code_verifier' => $codeVerifier, // required for OIDC/FAPI
]);
return redirect()->away($url);

// callback
$code = (string) request('code', '');
$state = (string) request('state', '');
$codeVerifier = (string) session('myinfo_state_'.$state, '');
session()->forget('myinfo_state_'.$state);

$token = MyInfo::exchangeToken($code, null, ['code_verifier' => $codeVerifier]);
$person = MyInfo::getPerson($token->getValue())->toArray();
```

## Legacy Env Aliases

Older env keys (`MYINFO_APP_*`, `MYINFO_API_*`, etc.) are still accepted as fallback.
