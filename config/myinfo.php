<?php

return [
    // Environment: sandbox | test | prod
    'env' => env('MYINFO_ENV', 'sandbox'),

    // OAuth client configuration
    'client_id' => env('MYINFO_CLIENT_ID', ''),
    'client_secret' => env('MYINFO_CLIENT_SECRET', ''),
    'redirect_uri' => env('MYINFO_REDIRECT_URI', ''),

    // Purpose string registered with MyInfo
    'purpose' => env('MYINFO_PURPOSE', ''),

    // Comma-separated list of attributes or array
    'attributes' => env('MYINFO_ATTRIBUTES', 'name,uinfin,dob,sex,race,nationality'),

    // Endpoints (override by environment if needed)
    'authorize_url' => env('MYINFO_BASE_URL_AUTH'),
    'token_url' => env('MYINFO_TOKEN_URL'),
    'person_url' => env('MYINFO_BASE_URL_API'),

    // Certificates / keys (either file path or base64 of the PEM contents)
    // - signing_cert_*: MyInfo's signing certificate (PUBLIC cert) — provided by MyInfo. Used to VERIFY JWS signatures.
    //   Accepts PEM format (.cer/.crt/.pem); if you have DER .cer, convert to PEM first.
    'signing_cert_path' => env('MYINFO_SIGNING_CERT_PATH', env('MYINFO_PUBLIC_CERT_PATH')),
    'signing_cert_b64' => env('MYINFO_SIGNING_CERT_B64', env('MYINFO_PUBLIC_CERT_B64')),

    // - decryption_key_*: YOUR application's RSA PRIVATE key — owned by you. Used to DECRYPT JWE payloads.
    //   The matching PUBLIC key/cert must be registered with MyInfo so they can encrypt to you.
    'decryption_key_path' => env('MYINFO_DECRYPTION_KEY_PATH', env('MYINFO_PRIVATE_KEY_PATH')),
    'decryption_key_b64' => env('MYINFO_DECRYPTION_KEY_B64', env('MYINFO_PRIVATE_KEY_B64')),
    'decryption_key_passphrase' => env('MYINFO_DECRYPTION_KEY_PASSPHRASE', env('MYINFO_PRIVATE_KEY_PASSPHRASE')),

    // HTTP timeout in milliseconds
    'timeout_ms' => (int) env('MYINFO_TIMEOUT_MS', 10000),
];

