<?php

return [
    // Required
    'client_id' => env('MYINFO_CLIENT_ID', ''),
    'redirect_uri' => env('MYINFO_REDIRECT_URI', ''),

    // Optional
    'timeout_ms' => (int) env('MYINFO_TIMEOUT_MS', 10000),

    'oidc' => [
        // Optional path to Singpass config JSON (contains CLIENT_ID/REDIRECT_URI/ISSUER_URL/KEYS).
        'config_path' => env('MYINFO_OIDC_CONFIG_PATH'),

        // Defaults to staging issuer.
        'issuer_url' => env('MYINFO_ISSUER_URL', 'https://stg-id.singpass.gov.sg/fapi'),

        // Must include openid.
        'scope' => env('MYINFO_SCOPES', 'openid uinfin name'),

        // Optional override for client_assertion aud claim.
        // Default behavior uses OIDC discovery issuer.
        'client_assertion_audience' => env('MYINFO_OIDC_CLIENT_ASSERTION_AUDIENCE'),

        // Retry controls for transient upstream errors.
        'retry_attempts' => (int) env('MYINFO_OIDC_RETRY_ATTEMPTS', 3),
        'retry_backoff_ms' => (int) env('MYINFO_OIDC_RETRY_BACKOFF_MS', 250),

        // Optional direct key inputs (JSON string or JSON file path)
        'private_sig_jwk_json' => env('MYINFO_OIDC_PRIVATE_SIG_JWK_JSON'),
        'private_sig_jwk_path' => env('MYINFO_OIDC_PRIVATE_SIG_JWK_PATH'),
        'public_sig_jwk_json' => env('MYINFO_OIDC_PUBLIC_SIG_JWK_JSON'),
        'public_sig_jwk_path' => env('MYINFO_OIDC_PUBLIC_SIG_JWK_PATH'),
        'private_enc_jwk_json' => env('MYINFO_OIDC_PRIVATE_ENC_JWK_JSON'),
        'private_enc_jwk_path' => env('MYINFO_OIDC_PRIVATE_ENC_JWK_PATH'),

        // Optional override for Singpass signing keys used to verify id_token/userinfo signatures.
        // Accepts either JWKS JSON ({ "keys": [...] }) or a single JWK object.
        // If set, runtime uses this instead of discovery jwks_uri.
        'verification_jwks_json' => env('MYINFO_OIDC_VERIFICATION_JWKS_JSON'),
        'verification_jwks_path' => env('MYINFO_OIDC_VERIFICATION_JWKS_PATH'),
    ],
];
