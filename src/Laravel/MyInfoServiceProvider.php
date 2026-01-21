<?php

namespace MyInfo\Laravel;

use Illuminate\Support\ServiceProvider;
use MyInfo\Config as MyInfoConfig;
use MyInfo\MyInfoClient;

/**
 * Laravel service provider for MyInfo integration.
 *
 * - Merges default config.
 * - Publishes config file and public assets.
 * - Binds MyInfoClient as a singleton.
 */
class MyInfoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/myinfo.php', 'myinfo');

        $this->app->singleton(MyInfoClient::class, function ($app) {
            $cfgArray = config('myinfo', []);
            $config = MyInfoConfig::fromArray(is_array($cfgArray) ? $cfgArray : []);
            return new MyInfoClient($config);
        });

        // Alias binding for convenience
        $this->app->alias(MyInfoClient::class, 'myinfo');
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../../config/myinfo.php' => config_path('myinfo.php'),
        ], 'myinfo-config');

        $this->publishes([
            __DIR__ . '/../../resources/assets/myinfo' => public_path('vendor/myinfo'),
        ], 'myinfo-assets');
    }
}

