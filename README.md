# phonemgr-socialite

Sign in with Phone Manager in a Laravel app: a [Socialite](https://laravel.com/docs/socialite) driver
`phonemgr` for Phone Manager's OpenID Connect provider, and verification of the tokens Phone Manager
signs when it calls the app's provisioning API.

## Install

The package is not on Packagist. Add the repository, then require it:

```json
"repositories": [
    { "type": "vcs", "url": "https://github.com/Vested-Networks/phonemgr-socialite" }
]
```

```bash
composer require vested-networks/phonemgr-socialite
```

The service provider is auto-discovered and registers the `phonemgr` driver.

## Configure

In `config/services.php`:

```php
'phonemgr' => [
    'issuer' => env('PHONEMGR_ISSUER'),             // public URL; the browser goes here, and `iss` must match it
    'internal_url' => env('PHONEMGR_INTERNAL_URL'), // where the app reaches Phone Manager server to server
    'client_id' => ...,
    'client_secret' => ...,
    'redirect' => ...,                               // the app's callback URL, registered in Phone Manager
],
```

`internal_url` may equal `issuer` when there is no private network between the app and Phone Manager.
The client id, secret and redirect can also be set at runtime, before `Socialite::driver('phonemgr')`.

## Sign in

```php
return Socialite::driver('phonemgr')->redirect();

// callback
$account = Socialite::driver('phonemgr')->user();
$account->getId();          // `sub`, permanent: match the local account by this only
$account->getRaw()['role']; // the person's role in this app
```

Authorization code flow with PKCE S256, scopes `openid profile email phonemgr`. The code is exchanged at
`{internal_url}/oauth/token`, and the account is read from the id_token, checked against the keys at
`{internal_url}/oauth/jwks` (cached for an hour, refetched once for an unknown key). A callback with
`error=access_denied` means Phone Manager refused the person; show that, do not retry.

## Provisioning API

Phone Manager creates, updates and deactivates the app's accounts by calling `PUT` and
`DELETE {provisioning-url}/owners/{sub}` with `Authorization: Bearer <JWT>`. Check that token in the
app's middleware:

```php
use VestedNetworks\PhoneManager\PhoneManagerTokens;

try {
    app(PhoneManagerTokens::class)->verifyProvisioning((string) $request->bearerToken(), $clientId);
} catch (UnexpectedValueException) {
    abort(401);
}
```

It accepts only an RS256 token signed with a key from Phone Manager's JWKS, with `iss` = the issuer,
`aud` = the app's client id, `sub` = `phonemgr`, and not expired.

## Tests

```bash
composer install
composer test
```
