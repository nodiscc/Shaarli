<?php

/**
 * Unpares UrlUtils's tests
 */

namespace Shaarli\Http;

use Shaarli\TestCase;

/**
 * Unitary tests for unparse_url()
 */
class UnparseUrlTest extends TestCase
{
    /**
     * Thanks for building nothing
     */
    public function testUnparseEmptyArray()
    {
        $this->assertEquals('', unparse_url([]));
    }

    /**
     * Rebuild a full-featured URL
     */
    public function testUnparseFull()
    {
        $ref = 'http://username:password@hostname:9090/path'
              . '?arg1=value1&arg2=value2#anchor';
        $this->assertEquals($ref, unparse_url(parse_url($ref)));
    }
}
