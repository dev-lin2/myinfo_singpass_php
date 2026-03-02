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
    private ?string $idToken;
    /** @var array<string,mixed>|null */
    private ?array $idTokenClaims;

    /**
     * @param array<string,mixed>|null $idTokenClaims
     */
    public function __construct(
        string $value,
        CarbonImmutable $expiresAt,
        ?string $tokenType = null,
        ?string $scope = null,
        ?string $idToken = null,
        ?array $idTokenClaims = null
    )
    {
        $this->value = $value;
        $this->expiresAt = $expiresAt;
        $this->tokenType = $tokenType;
        $this->scope = $scope;
        $this->idToken = $idToken;
        $this->idTokenClaims = $idTokenClaims;
    }

    public function getValue(): string { return $this->value; }
    public function getExpiresAt(): CarbonImmutable { return $this->expiresAt; }
    public function getTokenType(): ?string { return $this->tokenType; }
    public function getScope(): ?string { return $this->scope; }
    public function getIdToken(): ?string { return $this->idToken; }
    /** @return array<string,mixed>|null */
    public function getIdTokenClaims(): ?array { return $this->idTokenClaims; }
}
