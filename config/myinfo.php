<?php

return [
    // Environment: sandbox | test | prod
    'env' => env('MYINFO_ENV', 'sandbox'),
    // Flow mode: legacy | oidc | oidc_fapi | fapi
    'mode' => env('MYINFO_MODE', 'legacy'),

    // OAuth client configuration (canonical keys first, legacy keys as fallback)
    'client_id' => env('MYINFO_CLIENT_ID', env('MYINFO_APP_CLIENT_ID', '')),
    'client_secret' => env('MYINFO_CLIENT_SECRET', env('MYINFO_APP_CLIENT_SECRET', '')),
    'redirect_uri' => env('MYINFO_REDIRECT_URI', env('MYINFO_APP_REDIRECT_URL', '')),

    // Purpose string registered with MyInfo
    'purpose' => env('MYINFO_PURPOSE', 'demonstration'),

    // Comma-separated list of attributes or array
    'attributes' => env('MYINFO_ATTRIBUTES', 'name,uinfin,dob,sex,race,nationality'),

    // Endpoints (canonical keys first, legacy keys as fallback)
    'authorize_url' => env('MYINFO_BASE_URL_AUTH', env('MYINFO_API_AUTHORISE')),
    'token_url' => env('MYINFO_TOKEN_URL', env('MYINFO_API_TOKEN')),
    'person_url' => env('MYINFO_BASE_URL_API', env('MYINFO_API_PERSON')),

    // Certificates / keys (either file path or base64 of the PEM contents)
    // - signing_cert_*: MyInfo's PUBLIC signing certificate used to VERIFY JWS signatures.
    //   Accepts PEM format (.cer/.crt/.pem); if you have DER .cer, convert to PEM first.
    'signing_cert_path' => env('MYINFO_SIGNING_CERT_PATH', env('MYINFO_PUBLIC_CERT_PATH', env('MYINFO_SIGNATURE_CERT_PUBLIC_CERT'))),
    'signing_cert_b64' => env('MYINFO_SIGNING_CERT_B64', env('MYINFO_PUBLIC_CERT_B64')),

    // - decryption_key_*: Your application's RSA PRIVATE key used to DECRYPT JWE payloads.
    //   The matching PUBLIC key/cert must be registered with MyInfo so they can encrypt to you.
    'decryption_key_path' => env('MYINFO_DECRYPTION_KEY_PATH', env('MYINFO_PRIVATE_KEY_PATH', env('DEMO_APP_SIGNATURE_CERT_PRIVATE_KEY'))),
    'decryption_key_b64' => env('MYINFO_DECRYPTION_KEY_B64', env('MYINFO_PRIVATE_KEY_B64')),
    'decryption_key_passphrase' => env('MYINFO_DECRYPTION_KEY_PASSPHRASE', env('MYINFO_PRIVATE_KEY_PASSPHRASE')),

    // HTTP timeout in milliseconds
    'timeout_ms' => (int) env('MYINFO_TIMEOUT_MS', 10000),

    // OIDC/FAPI mode settings
    'oidc' => [
        // Can point to the Singpass demo config.json for quick setup.
        'config_path' => env('MYINFO_OIDC_CONFIG_PATH'),

        'issuer_url' => env('MYINFO_ISSUER_URL', 'https://stg-id.singpass.gov.sg/fapi'),
        'scope' => env('MYINFO_SCOPES', env('MYINFO_SCOPE', 'openid uinfin name')),

        'use_par' => env('MYINFO_OIDC_USE_PAR', true),
        'use_dpop' => env('MYINFO_OIDC_USE_DPOP', true),

        // Optional direct key inputs (JSON string or JSON file path)
        'private_sig_jwk_json' => env('MYINFO_OIDC_PRIVATE_SIG_JWK_JSON'),
        'private_sig_jwk_path' => env('MYINFO_OIDC_PRIVATE_SIG_JWK_PATH'),
        'public_sig_jwk_json' => env('MYINFO_OIDC_PUBLIC_SIG_JWK_JSON'),
        'public_sig_jwk_path' => env('MYINFO_OIDC_PUBLIC_SIG_JWK_PATH'),
        'private_enc_jwk_json' => env('MYINFO_OIDC_PRIVATE_ENC_JWK_JSON'),
        'private_enc_jwk_path' => env('MYINFO_OIDC_PRIVATE_ENC_JWK_PATH'),
    ],
];
