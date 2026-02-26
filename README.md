# MyInfo Singpass Package (Quick Start)

Simple Laravel package for MyInfo login + person data fetch.

## Required `.env`

```dotenv
MYINFO_ENV=sandbox
MYINFO_CLIENT_ID=...
MYINFO_CLIENT_SECRET=...
MYINFO_REDIRECT_URI=http://localhost:8080/verification/singpass/callback

# MyInfo signing cert (public cert)
MYINFO_SIGNING_CERT_PATH=./ssl/staging_myinfo_public_cert.cer

# Your app private key (must be private key, not cert)
MYINFO_DECRYPTION_KEY_PATH=./ssl/your_app_private_key.pem
```

## Optional `.env`

```dotenv
MYINFO_PURPOSE=demonstration
MYINFO_ATTRIBUTES=name,uinfin,dob,sex,race,nationality
MYINFO_TIMEOUT_MS=10000

# Optional endpoint overrides (sandbox defaults already built in)
MYINFO_BASE_URL_AUTH=https://sandbox.api.myinfo.gov.sg/com/v3/authorise
MYINFO_TOKEN_URL=https://sandbox.api.myinfo.gov.sg/com/v3/token
MYINFO_BASE_URL_API=https://sandbox.api.myinfo.gov.sg/com/v3/person

# Optional if your private key is encrypted
MYINFO_DECRYPTION_KEY_PASSPHRASE=
```

## Cert/Key Rules

- `MYINFO_SIGNING_CERT_PATH`: cert file can be `.cer`, `.crt`, or `.pem` (PEM or DER supported).
- `MYINFO_DECRYPTION_KEY_PATH`: must be a private key file.

## Minimal Usage

```php
use MyInfo\Laravel\Facades\MyInfo;

// 1) Redirect user to Singpass
$url = MyInfo::buildAuthorizeUrl();

// 2) Callback: exchange code for token
$token = MyInfo::exchangeToken($code);

// 3) Fetch person data
$person = MyInfo::getPerson($token->getValue());
// $person->toArray();
```

## Laravel Routes Example

```php
Route::get('/auth/myinfo/redirect', function () {
    return redirect()->away(MyInfo::buildAuthorizeUrl());
});

Route::get('/auth/myinfo/callback', function (\Illuminate\Http\Request $request) {
    $token = MyInfo::exchangeToken((string) $request->query('code', ''));
    return response()->json(MyInfo::getPerson($token->getValue())->toArray());
});
```

## Legacy Env Aliases

Legacy keys are still accepted as fallback for old projects (`MYINFO_APP_*`, `MYINFO_API_*`, etc.), but new setup should use the keys in this README.
