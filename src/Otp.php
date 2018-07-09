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

use DateTime;

class Otp implements OtpVerifierInterface
{
    /** @var \DateTime */
    private $dateTime;

    /**
     * @param null|\DateTime $dateTime
     */
    public function __construct(DateTime $dateTime = null)
    {
        if (null === $dateTime) {
            $dateTime = new DateTime();
        }
        $this->dateTime = $dateTime;
    }

    /**
     * @param string $totpSecret
     * @param int    $offset
     *
     * @return string
     */
    public function generate($totpSecret, $offset = 0)
    {
        $counter = \pack('J', $this->getCounterValue($offset));
        $hmac_result = \hash_hmac('sha1', $counter, $totpSecret, true);
        $offset = \ord($hmac_result[19]) & 0xf;
        $bin_code = (\ord($hmac_result[$offset]) & 0x7f) << 24
            | (\ord($hmac_result[$offset + 1]) & 0xff) << 16
            | (\ord($hmac_result[$offset + 2]) & 0xff) << 8
            | (\ord($hmac_result[$offset + 3]) & 0xff);
        $totp = (string) ($bin_code % \pow(10, 6));

        return \str_pad($totp, 6, '0', STR_PAD_LEFT);
    }

    /**
     * @param string $totpSecret
     * @param string $totpKey
     *
     * @return bool
     */
    public function verify($totpSecret, $totpKey)
    {
        foreach ([0, -1, 1] as $offset) {
            if (\hash_equals($this->generate($totpSecret, $offset), $totpKey)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param int $offset
     *
     * @return int
     */
    private function getCounterValue($offset)
    {
        return (int) \floor($this->dateTime->getTimestamp() / 30) + $offset;
    }
}
