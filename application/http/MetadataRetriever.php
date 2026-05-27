<?php

declare(strict_types=1);

namespace Shaarli\Http;

use Shaarli\Config\ConfigManager;
use function getAbsoluteUrl;
use function validateRedirectUrl;

/**
 * HTTP Tool used to extract metadata from external URL (title, description, etc.).
 */
class MetadataRetriever
{
    /** @var ConfigManager */
    protected $conf;

    /** @var HttpAccess */
    protected $httpAccess;

    public function __construct(ConfigManager $conf, HttpAccess $httpAccess)
    {
        $this->conf = $conf;
        $this->httpAccess = $httpAccess;
    }

    /**
     * Retrieve metadata for given URL.
     *
     * @return array [
     *                  'title' => <remote title>,
     *                  'description' => <remote description>,
     *                  'tags' => <remote keywords>,
     *               ]
     */
    public function retrieve(string $url): array
    {
        // SSRF protection: reject localhost, private IPs, and link-local addresses
        $urlObj = new Url($url);
        $host = $urlObj->getHost();

        // Block localhost hostname string
        if ($host === 'localhost' || $host === 'localhost.') {
            return [
                'title' => null,
                'description' => null,
                'tags' => null,
            ];
        }

        // Resolve hostname to IP and check against private ranges
        if ($host !== false) {
            $records = $this->resolveWithTimeout($host, 3);
            if (!empty($records)) {
                foreach ($records as $record) {
                    $ip = $record['ip'] ?? $record['ipv6'] ?? null;
                    if ($ip !== null && $this->isPrivateIp($ip)) {
                        return [
                            'title' => null,
                            'description' => null,
                            'tags' => null,
                        ];
                    }
                }
            }
        }

        $charset = null;
        $title = null;
        $description = null;
        $tags = null;
        $maxRedirects = 3;
        $redirectCount = 0;

        // Short timeout to keep the application responsive
        // The callback will fill $charset and $title with data from the downloaded page.
        // Loop to follow redirects with SSRF validation at each hop.
        $headers = null;
        while ($redirectCount <= $maxRedirects) {
            list($headers, $content) = $this->httpAccess->getHttpResponse(
                $url,
                $this->conf->get('general.download_timeout', 30),
                $this->conf->get('general.download_max_size', 4194304),
                $this->httpAccess->getCurlHeaderCallback($charset),
                $this->httpAccess->getCurlDownloadCallback(
                    $charset,
                    $title,
                    $description,
                    $tags,
                    $this->conf->get('general.retrieve_description'),
                    $this->conf->get('general.tags_separator', ' ')
                )
            );

            // Check for redirect response
            if (is_array($headers) && isset($headers[0]) && preg_match('#HTTP/[\d.]+ (\d{3})#', $headers[0], $matches)) {
                $statusCode = (int)$matches[1];
                if ($statusCode >= 300 && $statusCode < 400) {
                    $location = is_array($headers['Location'] ?? null)
                        ? end($headers['Location'])
                        : ($headers['Location'] ?? null);
                    if ($location === null || $location === '') {
                        break;
                    }
                    $url = getAbsoluteUrl($url, $location);
                    if (!validateRedirectUrl($url)) {
                        return [
                            'title' => null,
                            'description' => null,
                            'tags' => null,
                        ];
                    }
                    $redirectCount++;
                    // Reset metadata variables for the next hop
                    $charset = null;
                    $title = null;
                    $description = null;
                    $tags = null;
                    continue;
                }
            }
            break;
        }

        if (!empty($title) && strtolower($charset) !== 'utf-8') {
            $title = mb_convert_encoding($title, 'utf-8', $charset);
        }
        if (!empty($description) && strtolower($charset) !== 'utf-8') {
            $description = mb_convert_encoding($description, 'utf-8', $charset);
        }
        if (!empty($tags) && strtolower($charset) !== 'utf-8') {
            $tags = mb_convert_encoding($tags, 'utf-8', $charset);
        }

        return array_map([$this, 'cleanMetadata'], [
            'title' => $title,
            'description' => $description,
            'tags' => $tags,
        ]);
    }

    protected function cleanMetadata($data): ?string
    {
        return !is_string($data) || empty(trim($data)) ? null : trim($data);
    }

    /**
     * Resolve hostname to IP addresses with a timeout to prevent hanging on malicious domains.
     *
     * @param string $host   Hostname to resolve
     * @param int    $timeout Timeout in seconds
     *
     * @return array|null DNS records or null on timeout/failure
     */
    protected function resolveWithTimeout(string $host, int $timeout = 3): ?array
    {
        $resolved = null;
        $timedOut = false;

        if (function_exists('pcntl_signal') && function_exists('pcntl_alarm')) {
            pcntl_signal(SIGALRM, function () use (&$timedOut) {
                $timedOut = true;
            });
            pcntl_alarm($timeout);
            $records = @dns_get_record($host, DNS_A | DNS_AAAA, $authns, $addtl);
            pcntl_alarm(0);
            pcntl_signal(SIGALRM, SIG_DFL);
            if (!$timedOut && !empty($records)) {
                $resolved = $records;
            }
        } else {
            // Fallback: no timeout available, resolve directly
            $records = @dns_get_record($host, DNS_A | DNS_AAAA, $authns, $addtl);
            if (!empty($records)) {
                $resolved = $records;
            }
        }

        return $resolved;
    }

    /**
     * Check if an IP address is private, loopback, or link-local.
     *
     * @param string $ip IP address to check
     *
     * @return bool true if the IP is private/loopback/link-local
     */
    protected function isPrivateIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return (bool)(
                filter_var($ip, FILTER_FLAG_NO_PRIV_RANGE) === false
                && filter_var($ip, FILTER_FLAG_NO_RES_RANGE) === false
            );
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return (bool)(
                filter_var($ip, FILTER_FLAG_NO_PRIV_RANGE) === false
                || filter_var($ip, FILTER_FLAG_NO_RES_RANGE) === false
            );
        }

        return false;
    }
}
