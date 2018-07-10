<?php

/*
 * Copyright (c) 2018 François Kooman <fkooman@tuxed.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace fkooman\Totp;

use RuntimeException;

class Util
{
    /**
     * @param int $i
     *
     * @return string
     */
    public static function store64_be($i)
    {
        if (\PHP_VERSION_ID >= 50603) {
            return \pack('J', $i);
        }

        if (8 !== PHP_INT_SIZE) {
            throw new RuntimeException('only 64 bit PHP installations are supported');
        }

        return \pack('C', ($i >> 56) & 0xff).
            \pack('C', ($i >> 48) & 0xff).
            \pack('C', ($i >> 40) & 0xff).
            \pack('C', ($i >> 32) & 0xff).
            \pack('C', ($i >> 24) & 0xff).
            \pack('C', ($i >> 16) & 0xff).
            \pack('C', ($i >> 8) & 0xff).
            \pack('C', ($i & 0xff));
    }
}
