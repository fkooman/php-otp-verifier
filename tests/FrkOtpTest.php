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
            [new DateTime('1970-01-01 00:00:59'), $secretList['rfc6238#sha1'],   30, 'sha1',   8, '94287082'],
            [new DateTime('1970-01-01 00:00:59'), $secretList['rfc6238#sha256'], 30, 'sha256', 8, '46119246'],
            [new DateTime('1970-01-01 00:00:59'), $secretList['rfc6238#sha512'], 30, 'sha512', 8, '90693936'],
            [new DateTime('2005-03-18 01:58:29'), $secretList['rfc6238#sha1'],   30, 'sha1',   8, '07081804'],
            [new DateTime('2005-03-18 01:58:29'), $secretList['rfc6238#sha256'], 30, 'sha256', 8, '68084774'],
            [new DateTime('2005-03-18 01:58:29'), $secretList['rfc6238#sha512'], 30, 'sha512', 8, '25091201'],
            [new DateTime('2005-03-18 01:58:31'), $secretList['rfc6238#sha1'],   30, 'sha1',   8, '14050471'],
            [new DateTime('2005-03-18 01:58:31'), $secretList['rfc6238#sha256'], 30, 'sha256', 8, '67062674'],
            [new DateTime('2005-03-18 01:58:31'), $secretList['rfc6238#sha512'], 30, 'sha512', 8, '99943326'],
            [new DateTime('2009-02-13 23:31:30'), $secretList['rfc6238#sha1'],   30, 'sha1',   8, '89005924'],
            [new DateTime('2009-02-13 23:31:30'), $secretList['rfc6238#sha256'], 30, 'sha256', 8, '91819424'],
            [new DateTime('2009-02-13 23:31:30'), $secretList['rfc6238#sha512'], 30, 'sha512', 8, '93441116'],
            [new DateTime('2033-05-18 03:33:20'), $secretList['rfc6238#sha1'],   30, 'sha1',   8, '69279037'],
            [new DateTime('2033-05-18 03:33:20'), $secretList['rfc6238#sha256'], 30, 'sha256', 8, '90698825'],
            [new DateTime('2033-05-18 03:33:20'), $secretList['rfc6238#sha512'], 30, 'sha512', 8, '38618901'],
            [new DateTime('2603-10-11 11:33:20'), $secretList['rfc6238#sha1'],   30, 'sha1',   8, '65353130'],
            [new DateTime('2603-10-11 11:33:20'), $secretList['rfc6238#sha256'], 30, 'sha256', 8, '77737706'],
            [new DateTime('2603-10-11 11:33:20'), $secretList['rfc6238#sha512'], 30, 'sha512', 8, '47863826'],
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
    public function testTotp(DateTime $dateTime, $otpSecret, $totpPeriod, $otpHashAlgorithm, $otpDigits, $otpKey)
    {
        $this->assertSame($otpKey, FrkOtp::totp($dateTime, $otpSecret, $totpPeriod, $otpHashAlgorithm, $otpDigits));
        $this->assertTrue(FrkOtp::verifyTotp($dateTime, $otpSecret, $otpKey, $totpPeriod, $otpHashAlgorithm, $otpDigits));
    }

    public function testTotpWindow()
    {
        $this->assertSame('628637', FrkOtp::totp(new DateTime('2018-01-01 08:00:00'), '12345678901234567890', 30, 'sha1', 6));
        $this->assertSame('130937', FrkOtp::totp(new DateTime('2018-01-01 07:59:30'), '12345678901234567890', 30, 'sha1', 6));
        $this->assertSame('875993', FrkOtp::totp(new DateTime('2018-01-01 08:00:30'), '12345678901234567890', 30, 'sha1', 6));
        $this->assertSame('114787', FrkOtp::totp(new DateTime('2018-01-01 08:01:00'), '12345678901234567890', 30, 'sha1', 6));
        $this->assertSame('564860', FrkOtp::totp(new DateTime('2018-01-01 07:59:00'), '12345678901234567890', 30, 'sha1', 6));

        // we only support window of size 1, i.e. only codes valid in the
        // previous 30 seconds, and codes valid in the next 30 seconds from
        // "now"
        $this->assertTrue(FrkOtp::verifyTotp(new DateTime('2018-01-01 08:00:00'), '12345678901234567890', '628637', 30, 'sha1', 6));
        $this->assertTrue(FrkOtp::verifyTotp(new DateTime('2018-01-01 08:00:00'), '12345678901234567890', '130937', 30, 'sha1', 6));
        $this->assertTrue(FrkOtp::verifyTotp(new DateTime('2018-01-01 08:00:00'), '12345678901234567890', '875993', 30, 'sha1', 6));

        // codes outside this window are not supported
        $this->assertFalse(FrkOtp::verifyTotp(new DateTime('2018-01-01 08:00:00'), '12345678901234567890', '114787', 30, 'sha1', 6));
        $this->assertFalse(FrkOtp::verifyTotp(new DateTime('2018-01-01 08:00:00'), '12345678901234567890', '564860', 30, 'sha1', 6));
    }
}
