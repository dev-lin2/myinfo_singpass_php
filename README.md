# MyInfo (SingPass) PHP SDK (Laravel 8 / PHP 7.4)

PHP wrapper SDK for MyInfo integrations.

## Requirements
- PHP: 7.4.x
- Laravel: 8.x
- PHP extensions: `ext-openssl`, `ext-json`
- Composer packages: `guzzlehttp/guzzle:^7.0`, `web-token/jwt-framework:^2.2`, `nesbot/carbon:^2.0`, `psr/log:^1.1`

## Install
- Install packages:
  - `composer require guzzlehttp/guzzle:^7.0 web-token/jwt-framework:^2.2 nesbot/carbon:^2.0 psr/log:^1.1`
- Register (if not auto-discovered) in `config/app.php`:
  - Provider: `MyInfo\Laravel\MyInfoServiceProvider::class`
  - Alias: `'MyInfo' => MyInfo\Laravel\Facades\MyInfo::class`
- Publish config and assets:
  - `php artisan vendor:publish --tag=myinfo-config`
  - `php artisan vendor:publish --tag=myinfo-assets`

## Configure
Add to `.env` (examples):

```
MYINFO_ENV=sandbox
MYINFO_CLIENT_ID=...
MYINFO_CLIENT_SECRET=...
MYINFO_REDIRECT_URI=https://your-app.example.com/auth/myinfo/callback
MYINFO_PURPOSE=demonstration
MYINFO_ATTRIBUTES=name,uinfin,dob,sex,race

# Keys (provide path or base64 of the PEM contents)
# MyInfo's PUBLIC signing certificate — used to VERIFY JWS
MYINFO_SIGNING_CERT_PATH=/path/to/myinfo_signing_public.crt
# MYINFO_SIGNING_CERT_B64=base64-PEM

# YOUR RSA PRIVATE key — used to DECRYPT JWE (register its public key with MyInfo)
MYINFO_DECRYPTION_KEY_PATH=/path/to/your_decryption_private_key.pem
# MYINFO_DECRYPTION_KEY_B64=base64-PEM
MYINFO_DECRYPTION_KEY_PASSPHRASE=

MYINFO_TIMEOUT_MS=10000
```

Notes:
- `.cer` files must be PEM; convert DER to PEM if needed.
- `signing_cert_*` is from MyInfo; `decryption_key_*` is your private key.

## Usage (Laravel)

Routes (`routes/web.php`):

```php
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\MyInfoAuthController;

Route::get('/auth/myinfo/redirect', [MyInfoAuthController::class, 'redirect'])->name('myinfo.redirect');
Route::get('/auth/myinfo/callback', [MyInfoAuthController::class, 'callback'])->name('myinfo.callback');
```

Controller (`app/Http/Controllers/MyInfoAuthController.php`):

```php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use MyInfo\Laravel\Facades\MyInfo;

class MyInfoAuthController extends Controller
{
    public function redirect()
    {
        return redirect()->away(MyInfo::buildAuthorizeUrl());
    }

    public function callback(Request $request)
    {
        $code = (string) $request->query('code', '');
        $token = MyInfo::exchangeToken($code);
        // If your environment requires UIN/FIN in the path, supply it as third arg
        $person = MyInfo::getPerson($token->getValue());
        // $person = MyInfo::getPerson($token->getValue(), null, $uinfin);
        return response()->json($person->toArray());
    }
}
```

Blade (optional button/assets):

```blade
<script src="{{ asset('vendor/myinfo/login.js') }}" defer></script>
<a href="{{ MyInfo::buildAuthorizeUrl() }}">
  <img src="{{ asset('vendor/myinfo/singpass-button.svg') }}" alt="Sign in with Singpass" />
</a>
```
