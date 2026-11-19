<?php

namespace VestedNetworks\PhoneManager\Tests;

use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\SocialiteServiceProvider;
use Orchestra\Testbench\TestCase;
use UnexpectedValueException;
use VestedNetworks\PhoneManager\PhoneManagerServiceProvider;
use VestedNetworks\PhoneManager\PhoneManagerTokens;

class PhoneManagerTest extends TestCase
{
    private const ISSUER = 'https://phonemgr.test';

    private const INTERNAL = 'http://phonemgr.internal';

    private const CLIENT = 'app-client';

    /** @var array<string, array{0: string, 1: array<string, string>}> private keys and their JWKs, by kid */
    private static array $keys = [];

    /** @var list<string> the kids Phone Manager's JWKS publishes now */
    private array $published = ['kid-1'];

    protected function getPackageProviders($app): array
    {
        return [SocialiteServiceProvider::class, PhoneManagerServiceProvider::class];
    }

    protected function setUp(): void
    {
        parent::setUp();

        config(['services.phonemgr' => [
            'issuer' => self::ISSUER,
            'internal_url' => self::INTERNAL,
            'client_id' => self::CLIENT,
            'client_secret' => 'secret',
            'redirect' => 'https://app.test/auth/phonemgr/callback',
        ]]);
        Http::fake([self::INTERNAL.'/oauth/jwks' => fn () => Http::response(['keys' => array_map(fn (string $kid) => self::key($kid)[1], $this->published)])]);
    }

    public function test_sign_in_starts_at_the_public_issuer_with_pkce(): void
    {
        $location = Socialite::driver('phonemgr')->setRequest($this->request())->redirect()->getTargetUrl();

        $this->assertStringStartsWith(self::ISSUER.'/oauth/authorize?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $this->assertSame(self::CLIENT, $query['client_id']);
        $this->assertSame('openid profile email phonemgr', $query['scope']);
        $this->assertSame('S256', $query['code_challenge_method']);
    }

    public function test_the_code_is_exchanged_internally_and_the_account_comes_from_the_id_token(): void
    {
        Http::fake([self::INTERNAL.'/oauth/token' => Http::response([
            'access_token' => 'at',
            'id_token' => self::token(['sub' => 'the-sub', 'name' => 'Ada', 'email' => 'ada@vested.test', 'role' => 'owner']),
        ])]);
        $request = $this->request(['code' => 'abc', 'state' => 's1']);
        $request->session()->put(['state' => 's1', 'code_verifier' => str_repeat('v', 64)]);

        $account = Socialite::driver('phonemgr')->setRequest($request)->user();

        $this->assertSame('the-sub', $account->getId());
        $this->assertSame('ada@vested.test', $account->getEmail());
        $this->assertSame('owner', $account->getRaw()['role']);
        Http::assertSent(fn ($sent) => $sent->url() === self::INTERNAL.'/oauth/token' && $sent['code_verifier'] === str_repeat('v', 64));
    }

    public function test_tokens_for_another_app_issuer_or_time_are_refused(): void
    {
        foreach ([['aud' => 'other-client'], ['iss' => 'https://evil.test'], ['exp' => time() - 10]] as $claims) {
            $this->assertRefused(fn () => app(PhoneManagerTokens::class)->verify(self::token($claims), self::CLIENT));
        }
    }

    public function test_a_token_signed_with_an_unknown_key_is_refused(): void
    {
        $this->assertRefused(fn () => app(PhoneManagerTokens::class)->verify(self::token([], 'kid-forged'), self::CLIENT));
    }

    public function test_a_rotated_key_is_fetched_without_a_restart(): void
    {
        app(PhoneManagerTokens::class)->verify(self::token(), self::CLIENT);
        $this->published = ['kid-2'];

        $claims = app(PhoneManagerTokens::class)->verify(self::token([], 'kid-2'), self::CLIENT);

        $this->assertSame('phonemgr', $claims['sub']);
    }

    public function test_a_provisioning_token_must_have_sub_phonemgr(): void
    {
        $tokens = app(PhoneManagerTokens::class);

        $this->assertSame('phonemgr', $tokens->verifyProvisioning(self::token(), self::CLIENT)['sub']);
        $this->assertRefused(fn () => $tokens->verifyProvisioning(self::token(['sub' => 'someone']), self::CLIENT));
    }

    /**
     * @param  array<string, string>  $query
     */
    private function request(array $query = []): Request
    {
        $request = Request::create('/auth/phonemgr', 'GET', $query);
        $request->setLaravelSession($this->app['session.store']);

        return $request;
    }

    private function assertRefused(callable $verify): void
    {
        try {
            $verify();
            $this->fail('The token was accepted.');
        } catch (UnexpectedValueException) {
            $this->addToAssertionCount(1);
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private static function token(array $claims = [], string $kid = 'kid-1'): string
    {
        return JWT::encode([
            'iss' => self::ISSUER,
            'aud' => self::CLIENT,
            'sub' => 'phonemgr',
            'iat' => time(),
            'exp' => time() + 300,
            ...$claims,
        ], self::key($kid)[0], 'RS256', $kid);
    }

    /**
     * @return array{0: string, 1: array<string, string>}
     */
    private static function key(string $kid): array
    {
        if (! isset(self::$keys[$kid])) {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            openssl_pkey_export($key, $private);
            $rsa = openssl_pkey_get_details($key)['rsa'];
            $b64 = fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
            self::$keys[$kid] = [$private, ['kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => $kid, 'n' => $b64($rsa['n']), 'e' => $b64($rsa['e'])]];
        }

        return self::$keys[$kid];
    }
}
