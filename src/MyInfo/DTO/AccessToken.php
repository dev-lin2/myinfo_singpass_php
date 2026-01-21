<?php

namespace MyInfo\DTO;

use Carbon\CarbonImmutable;

/**
 * Value object for OAuth Access Token response.
 */
class AccessToken
{
    private string $value;
    private CarbonImmutable $expiresAt;
    private ?string $tokenType;
    private ?string $scope;

    public function __construct(string $value, CarbonImmutable $expiresAt, ?string $tokenType = null, ?string $scope = null)
    {
        $this->value = $value;
        $this->expiresAt = $expiresAt;
        $this->tokenType = $tokenType;
        $this->scope = $scope;
    }

    public function getValue(): string { return $this->value; }
    public function getExpiresAt(): CarbonImmutable { return $this->expiresAt; }
    public function getTokenType(): ?string { return $this->tokenType; }
    public function getScope(): ?string { return $this->scope; }
}

