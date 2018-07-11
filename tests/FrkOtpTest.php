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

namespace fkooman\Otp\Tests;

use DateTime;
use fkooman\Otp\FrkOtp;
use PHPUnit\Framework\TestCase;

class FrkOtpTest extends TestCase
{
    public function hotpTestVectors()
    {
        $secretList = [
            'rfc4226#sha1' => '12345678901234567890',
        ];

        return [
            // RFC 4226
            [$secretList['rfc4226#sha1'], 0, 'sha1', 6, '755224'],
            [$secretList['rfc4226#sha1'], 1, 'sha1', 6, '287082'],
            [$secretList['rfc4226#sha1'], 2, 'sha1', 6, '359152'],
            [$secretList['rfc4226#sha1'], 3, 'sha1', 6, '969429'],
            [$secretList['rfc4226#sha1'], 4, 'sha1', 6, '338314'],
            [$secretList['rfc4226#sha1'], 5, 'sha1', 6, '254676'],
            [$secretList['rfc4226#sha1'], 6, 'sha1', 6, '287922'],
            [$secretList['rfc4226#sha1'], 7, 'sha1', 6, '162583'],
            [$secretList['rfc4226#sha1'], 8, 'sha1', 6, '399871'],
            [$secretList['rfc4226#sha1'], 9, 'sha1', 6, '520489'],
        ];
    }

    public function totpTestVectors()
    {
        $secretList = [
            'rfc6238#sha1' => '12345678901234567890',
            'rfc6238#sha256' => '12345678901234567890123456789012',
            'rfc6238#sha512' => '1234567890123456789012345678901234567890123456789012345678901234',
        ];

        return [
            // RFC 6238
            [$secretList['rfc6238#sha1'],   30, 'sha1',   8, new DateTime('1970-01-01 00:00:59'), '94287082'],
            [$secretList['rfc6238#sha256'], 30, 'sha256', 8, new DateTime('1970-01-01 00:00:59'), '46119246'],
            [$secretList['rfc6238#sha512'], 30, 'sha512', 8, new DateTime('1970-01-01 00:00:59'), '90693936'],
            [$secretList['rfc6238#sha1'],   30, 'sha1',   8, new DateTime('2005-03-18 01:58:29'), '07081804'],
            [$secretList['rfc6238#sha256'], 30, 'sha256', 8, new DateTime('2005-03-18 01:58:29'), '68084774'],
            [$secretList['rfc6238#sha512'], 30, 'sha512', 8, new DateTime('2005-03-18 01:58:29'), '25091201'],
            [$secretList['rfc6238#sha1'],   30, 'sha1',   8, new DateTime('2005-03-18 01:58:31'), '14050471'],
            [$secretList['rfc6238#sha256'], 30, 'sha256', 8, new DateTime('2005-03-18 01:58:31'), '67062674'],
            [$secretList['rfc6238#sha512'], 30, 'sha512', 8, new DateTime('2005-03-18 01:58:31'), '99943326'],
            [$secretList['rfc6238#sha1'],   30, 'sha1',   8, new DateTime('2009-02-13 23:31:30'), '89005924'],
            [$secretList['rfc6238#sha256'], 30, 'sha256', 8, new DateTime('2009-02-13 23:31:30'), '91819424'],
            [$secretList['rfc6238#sha512'], 30, 'sha512', 8, new DateTime('2009-02-13 23:31:30'), '93441116'],
            [$secretList['rfc6238#sha1'],   30, 'sha1',   8, new DateTime('2033-05-18 03:33:20'), '69279037'],
            [$secretList['rfc6238#sha256'], 30, 'sha256', 8, new DateTime('2033-05-18 03:33:20'), '90698825'],
            [$secretList['rfc6238#sha512'], 30, 'sha512', 8, new DateTime('2033-05-18 03:33:20'), '38618901'],
            [$secretList['rfc6238#sha1'],   30, 'sha1',   8, new DateTime('2603-10-11 11:33:20'), '65353130'],
            [$secretList['rfc6238#sha256'], 30, 'sha256', 8, new DateTime('2603-10-11 11:33:20'), '77737706'],
            [$secretList['rfc6238#sha512'], 30, 'sha512', 8, new DateTime('2603-10-11 11:33:20'), '47863826'],
        ];
    }

    /**
     * @dataProvider hotpTestVectors
     *
     * @param string $otpSecret
     * @param int    $otpCounter
     * @param string $otpHashAlgorithm
     * @param int    $otpDigits
     * @param string $otpKey
     */
    public function testHotp($otpSecret, $otpCounter, $otpHashAlgorithm, $otpDigits, $otpKey)
    {
        $this->assertSame($otpKey, FrkOtp::hotp($otpSecret, $otpCounter, $otpHashAlgorithm, $otpDigits));
        $this->assertTrue(FrkOtp::verifyHotp($otpSecret, $otpKey, $otpCounter, $otpHashAlgorithm, $otpDigits));
    }

    /**
     * @dataProvider totpTestVectors
     *
     * @param string    $otpSecret
     * @param int       $totpPeriod
     * @param string    $otpHashAlgorithm
     * @param int       $otpDigits
     * @param \DateTime $dateTime
     * @param string    $otpKey
     */
    public function testTotp($otpSecret, $totpPeriod, $otpHashAlgorithm, $otpDigits, DateTime $dateTime, $otpKey)
    {
        $this->assertSame($otpKey, FrkOtp::totp($otpSecret, $totpPeriod, $otpHashAlgorithm, $otpDigits, $dateTime));
        $this->assertTrue(FrkOtp::verifyTotp($otpSecret, $otpKey, $totpPeriod, $otpHashAlgorithm, $otpDigits, $dateTime));
    }
}
