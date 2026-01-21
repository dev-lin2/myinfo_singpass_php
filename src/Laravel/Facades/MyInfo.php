<?php

namespace MyInfo\Laravel\Facades;

use Illuminate\Support\Facades\Facade;
use MyInfo\MyInfoClient;

/**
 * Facade for convenient access to the MyInfoClient in Laravel apps.
 *
 * Usage: MyInfo::buildAuthorizeUrl();
 */
class MyInfo extends Facade
{
    protected static function getFacadeAccessor()
    {
        return MyInfoClient::class;
    }
}

