<?php

namespace MyInfo\DTO;

/**
 * Strongly-typed wrapper for a MyInfo Person payload.
 * Provides array accessors and convenience getters for common attributes.
 */
class Person
{
    /** @var array<string,mixed> */
    private array $data;

    /**
     * @param array<string,mixed> $data
     */
    public function __construct(array $data)
    {
        $this->data = $data;
    }

    /**
     * Returns the raw data array.
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return $this->data;
    }

    public function getUinFin(): ?string
    {
        return $this->data['uinfin'] ?? null;
    }

    public function getName(): ?string
    {
        return $this->data['name']['value'] ?? null;
    }
}

