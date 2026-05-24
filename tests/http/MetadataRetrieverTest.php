<?php

declare(strict_types=1);

namespace Shaarli\Http;

use PHPUnit\Framework\TestCase;
use Shaarli\Config\ConfigManager;

class MetadataRetrieverTest extends TestCase
{
    /** @var MetadataRetriever */
    protected $retriever;

    /** @var ConfigManager */
    protected $conf;

    /** @var HttpAccess */
    protected $httpAccess;

    public function setUp(): void
    {
        $this->conf = $this->createMock(ConfigManager::class);
        $this->httpAccess = $this->createMock(HttpAccess::class);
        $this->retriever = new MetadataRetriever($this->conf, $this->httpAccess);

        $this->conf->method('get')->willReturnCallback(function (string $param, $default) {
            return $default === null ? $param : $default;
        });
    }

    /**
     * Test metadata retrieve() with values returned
     */
    public function testFullRetrieval(): void
    {
        $url = 'https://domain.tld/link';
        $remoteTitle = 'Remote Title ';
        $remoteDesc = 'Sometimes the meta description is relevant.';
        $remoteTags = 'abc def';
        $remoteCharset = 'utf-8';

        $expectedResult = [
            'title' => trim($remoteTitle),
            'description' => $remoteDesc,
            'tags' => $remoteTags,
        ];

        $this->httpAccess
            ->expects(static::once())
            ->method('getCurlHeaderCallback')
            ->willReturnCallback(
                function (&$charset) use (
                    $remoteCharset
                ): callable {
                    return function () use (
                        &$charset,
                        $remoteCharset
                    ): void {
                        $charset = $remoteCharset;
                    };
                }
            )
        ;
        $this->httpAccess
            ->expects(static::once())
            ->method('getCurlDownloadCallback')
            ->willReturnCallback(
                function (
                    &$charset,
                    &$title,
                    &$description,
                    &$tags
                ) use (
                    $remoteCharset,
                    $remoteTitle,
                    $remoteDesc,
                    $remoteTags
                ): callable {
                    return function () use (
                        &$charset,
                        &$title,
                        &$description,
                        &$tags,
                        $remoteCharset,
                        $remoteTitle,
                        $remoteDesc,
                        $remoteTags
                    ): void {
                        static::assertSame($remoteCharset, $charset);

                        $title = $remoteTitle;
                        $description = $remoteDesc;
                        $tags = $remoteTags;
                    };
                }
            )
        ;
        $this->httpAccess
            ->expects(static::once())
            ->method('getHttpResponse')
            ->with($url, 30, 4194304)
            ->willReturnCallback(function ($url, $timeout, $maxBytes, $headerCallback, $dlCallback): void {
                $headerCallback();
                $dlCallback();
            })
        ;

        $result = $this->retriever->retrieve($url);

        static::assertSame($expectedResult, $result);
    }

    /**
     * Test metadata retrieve() without any value
     */
    public function testEmptyRetrieval(): void
    {
        $url = 'https://domain.tld/link';

        $expectedResult = [
            'title' => null,
            'description' => null,
            'tags' => null,
        ];

        $this->httpAccess
            ->expects(static::once())
            ->method('getCurlDownloadCallback')
            ->willReturnCallback(
                function (): callable {
                    return function (): void {
                    };
                }
            )
        ;
        $this->httpAccess
            ->expects(static::once())
            ->method('getCurlHeaderCallback')
            ->willReturnCallback(
                function (): callable {
                    return function (): void {
                    };
                }
            )
        ;
        $this->httpAccess
            ->expects(static::once())
            ->method('getHttpResponse')
            ->with($url, 30, 4194304)
            ->willReturnCallback(function ($url, $timeout, $maxBytes, $headerCallback, $dlCallback): void {
                $headerCallback();
                $dlCallback();
            })
        ;

        $result = $this->retriever->retrieve($url);

        static::assertSame($expectedResult, $result);
    }

    /**
     * Test that localhost URLs are rejected (SSRF protection).
     */
    public function testSsrfLocalhostRejected(): void
    {
        $result = $this->retriever->retrieve('http://localhost/path');
        static::assertSame(['title' => null, 'description' => null, 'tags' => null], $result);

        $result = $this->retriever->retrieve('http://localhost./path');
        static::assertSame(['title' => null, 'description' => null, 'tags' => null], $result);
    }

    /**
     * Test that URLs with private IP addresses are rejected (SSRF protection).
     */
    public function testSsrfPrivateIpRejected(): void
    {
        $privateIps = [
            '127.0.0.1',
            '127.0.0.2',
            '10.0.0.1',
            '10.255.255.255',
            '172.16.0.1',
            '172.31.255.255',
            '192.168.0.1',
            '192.168.255.255',
            '169.254.169.254',
        ];

        foreach ($privateIps as $ip) {
            $result = $this->retriever->retrieve("http://{$ip}/path");
            static::assertSame(['title' => null, 'description' => null, 'tags' => null], $result, "Failed to reject private IP: {$ip}");
        }
    }

    /**
     * Test that URLs with public IPs pass through to the HTTP layer.
     */
    public function testSsrfPublicIpAllowed(): void
    {
        $url = 'https://93.184.216.34/link';
        $remoteTitle = 'Remote Title';
        $remoteDesc = 'A description';
        $remoteTags = 'tag1';

        $this->httpAccess
            ->expects(static::once())
            ->method('getCurlHeaderCallback')
            ->willReturnCallback(function (): callable {
                return function (): void {
                };
            });
        $this->httpAccess
            ->expects(static::once())
            ->method('getCurlDownloadCallback')
            ->willReturnCallback(function (
                &$charset,
                &$title,
                &$description,
                &$tags
            ): callable {
                return function () use (&$charset, &$title, &$description, &$tags): void {
                    $charset = 'utf-8';
                    $title = 'Remote Title';
                    $description = 'A description';
                    $tags = 'tag1';
                };
            });
        $this->httpAccess
            ->expects(static::once())
            ->method('getHttpResponse')
            ->with($url, 30, 4194304)
            ->willReturnCallback(function ($url, $timeout, $maxBytes, $headerCallback, $dlCallback): void {
                $headerCallback();
                $dlCallback();
            });

        $result = $this->retriever->retrieve($url);

        static::assertSame([
            'title' => 'Remote Title',
            'description' => 'A description',
            'tags' => 'tag1',
        ], $result);
    }

    /**
     * Test that unresolvable hosts return empty metadata.
     */
    public function testSsrfInvalidHostRejected(): void
    {
        $result = $this->retriever->retrieve('http://thisdomaindoesnotexist12345.invalid/path');
        static::assertSame(['title' => null, 'description' => null, 'tags' => null], $result);
    }
}
