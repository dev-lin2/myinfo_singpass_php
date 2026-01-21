<?php

namespace MyInfo\Http;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\GuzzleException;
use MyInfo\Exceptions\HttpException;
use Psr\Http\Message\ResponseInterface;

/**
 * Thin wrapper around Guzzle for consistent timeouts and error wrapping.
 */
class HttpClient
{
    /** @var GuzzleClient */
    private GuzzleClient $client;

    public function __construct(int $timeoutMs = 10000)
    {
        $this->client = new GuzzleClient([
            'timeout' => max(1, $timeoutMs / 1000),
            'http_errors' => false,
        ]);
    }

    /**
     * Perform a POST request with form-params.
     *
     * @param array<string,string> $formParams
     */
    public function postForm(string $url, array $formParams, array $headers = []): ResponseInterface
    {
        try {
            $response = $this->client->request('POST', $url, [
                'headers' => $headers,
                'form_params' => $formParams,
            ]);
        } catch (GuzzleException $e) {
            throw new HttpException('HTTP POST failed: ' . $e->getMessage(), null, $e);
        }

        $this->guardResponse($response, 'POST', $url);
        return $response;
    }

    /**
     * Perform a GET request with headers and query parameters.
     *
     * @param array<string,string> $query
     * @param array<string,string> $headers
     */
    public function get(string $url, array $query = [], array $headers = []): ResponseInterface
    {
        try {
            $response = $this->client->request('GET', $url, [
                'headers' => $headers,
                'query' => $query,
            ]);
        } catch (GuzzleException $e) {
            throw new HttpException('HTTP GET failed: ' . $e->getMessage(), null, $e);
        }

        $this->guardResponse($response, 'GET', $url);
        return $response;
    }

    private function guardResponse(ResponseInterface $response, string $method, string $url): void
    {
        $status = $response->getStatusCode();
        if ($status >= 200 && $status < 300) {
            return;
        }
        $body = (string) $response->getBody();
        $msg = sprintf('%s %s failed with status %d', $method, $url, $status);
        if ($body !== '') {
            $msg .= ' — ' . substr($body, 0, 500);
        }
        throw new HttpException($msg, $response);
    }
}

