<?php

namespace VestedNetworks\PhoneManager;

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Http;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\User;

/**
 * Socialite driver `phonemgr`: Phone Manager's OpenID Connect sign-in. Authorization code with PKCE;
 * the browser goes to the public issuer (`services.phonemgr.issuer`), the code is exchanged at
 * `services.phonemgr.internal_url`. The account comes from the verified id_token, which carries `sub`,
 * `name`, `email` and `role`, since Phone Manager has no userinfo endpoint.
 */
class PhoneManagerProvider extends AbstractProvider
{
    protected $scopes = ['openid', 'profile', 'email', 'phonemgr'];

    protected $scopeSeparator = ' ';

    protected $usesPKCE = true;

    public function user(): User
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());
        $claims = app(PhoneManagerTokens::class)->verify((string) Arr::get($response, 'id_token'), $this->clientId);

        return $this->user = $this->mapUserToObject($claims)->setToken((string) Arr::get($response, 'access_token'));
    }

    /**
     * The code exchange, through Laravel's HTTP client rather than Socialite's own Guzzle.
     *
     * @return array<string, mixed>
     */
    public function getAccessTokenResponse($code): array
    {
        return Http::asForm()->acceptJson()->timeout(10)
            ->post($this->getTokenUrl(), $this->getTokenFields($code))
            ->throw()
            ->json();
    }

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase(rtrim((string) config('services.phonemgr.issuer'), '/').'/oauth/authorize', $state);
    }

    protected function getTokenUrl(): string
    {
        return rtrim((string) config('services.phonemgr.internal_url'), '/').'/oauth/token';
    }

    /**
     * @return array<string, mixed>
     */
    protected function getUserByToken($token): array
    {
        return [];
    }

    /**
     * @param  array<string, mixed>  $user  the id_token's claims
     */
    protected function mapUserToObject(array $user): User
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['sub'] ?? null,
            'name' => $user['name'] ?? null,
            'email' => $user['email'] ?? null,
        ]);
    }
}
