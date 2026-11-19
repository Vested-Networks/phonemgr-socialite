<?php

namespace VestedNetworks\PhoneManager;

use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Facades\Socialite;

/** Registers the Socialite driver `phonemgr`, configured from `services.phonemgr`. */
class PhoneManagerServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Socialite::extend('phonemgr', fn () => Socialite::buildProvider(PhoneManagerProvider::class, config('services.phonemgr')));
    }
}
