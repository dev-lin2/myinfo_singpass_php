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
        $direct = $this->data['uinfin'] ?? null;
        if (is_string($direct) && $direct !== '') {
            return $direct;
        }

        $nested = $this->data['person_info']['uinfin']['value'] ?? null;
        return is_string($nested) && $nested !== '' ? $nested : null;
    }

    public function getName(): ?string
    {
        $direct = $this->data['name']['value'] ?? null;
        if (is_string($direct) && $direct !== '') {
            return $direct;
        }

        $nested = $this->data['person_info']['name']['value'] ?? null;
        return is_string($nested) && $nested !== '' ? $nested : null;
    }
}
