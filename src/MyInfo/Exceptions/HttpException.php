<?php

namespace MyInfo\Exceptions;

use RuntimeException;
use Psr\Http\Message\ResponseInterface;

/**
 * Wraps HTTP layer errors with optional response context.
 */
class HttpException extends RuntimeException
{
    /** @var ResponseInterface|null */
    protected $response;

    public function __construct(string $message, ?ResponseInterface $response = null, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->response = $response;
    }

    /**
     * Returns the related HTTP response if available.
     */
    public function getResponse(): ?ResponseInterface
    {
        return $this->response;
    }
}

