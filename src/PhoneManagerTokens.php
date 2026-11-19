<?php

namespace VestedNetworks\PhoneManager;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Throwable;
use UnexpectedValueException;

/**
 * Checks a JWT from Phone Manager: an id_token at sign-in, or the bearer token on a provisioning call.
 * Its signature must match a key from Phone Manager's JWKS, read from `services.phonemgr.internal_url`
 * and cached; its `iss` must be `services.phonemgr.issuer` and `aud` the app's client id. A token signed
 * with a key the cache does not know refetches the JWKS once, so a key rotation needs no restart.
 */
class PhoneManagerTokens
{
    private const CACHE_KEY = 'phonemgr.jwks';

    /**
     * @return array<string, mixed> the token's claims
     *
     * @throws UnexpectedValueException when the token is not valid for this audience
     */
    public function verify(string $jwt, string $audience): array
    {
        try {
            $claims = (array) JWT::decode($jwt, JWK::parseKeySet($this->keys()));
        } catch (Throwable) {
            Cache::forget(self::CACHE_KEY);
            try {
                $claims = (array) JWT::decode($jwt, JWK::parseKeySet($this->keys()));
            } catch (Throwable $e) {
                throw new UnexpectedValueException('The Phone Manager token is not valid: '.$e->getMessage(), previous: $e);
            }
        }

        $audiences = (array) ($claims['aud'] ?? []);
        if (($claims['iss'] ?? null) !== config('services.phonemgr.issuer') || ! in_array($audience, $audiences, true)) {
            throw new UnexpectedValueException('The Phone Manager token was not issued for this app.');
        }

        return $claims;
    }

    /**
     * The bearer token of a provisioning call: a valid token whose `sub` is `phonemgr`.
     *
     * @return array<string, mixed> the token's claims
     *
     * @throws UnexpectedValueException when it is not Phone Manager's provisioning token for this audience
     */
    public function verifyProvisioning(string $jwt, string $audience): array
    {
        $claims = $this->verify($jwt, $audience);
        if (($claims['sub'] ?? null) !== 'phonemgr') {
            throw new UnexpectedValueException('Not a Phone Manager provisioning token.');
        }

        return $claims;
    }

    /**
     * @return array{keys: list<array<string, string>>}
     */
    private function keys(): array
    {
        return Cache::remember(self::CACHE_KEY, now()->addHour(), fn (): array => Http::timeout(10)
            ->get(rtrim((string) config('services.phonemgr.internal_url'), '/').'/oauth/jwks')
            ->throw()
            ->json());
    }
}
