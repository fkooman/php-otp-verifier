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
            ['755224', $secretList['rfc4226#sha1'], 'sha1', 6, 0],
            ['287082', $secretList['rfc4226#sha1'], 'sha1', 6, 1],
            ['359152', $secretList['rfc4226#sha1'], 'sha1', 6, 2],
            ['969429', $secretList['rfc4226#sha1'], 'sha1', 6, 3],
            ['338314', $secretList['rfc4226#sha1'], 'sha1', 6, 4],
            ['254676', $secretList['rfc4226#sha1'], 'sha1', 6, 5],
            ['287922', $secretList['rfc4226#sha1'], 'sha1', 6, 6],
            ['162583', $secretList['rfc4226#sha1'], 'sha1', 6, 7],
            ['399871', $secretList['rfc4226#sha1'], 'sha1', 6, 8],
            ['520489', $secretList['rfc4226#sha1'], 'sha1', 6, 9],
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
            ['94287082', $secretList['rfc6238#sha1'],   'sha1',   8, new DateTime('1970-01-01 00:00:59'), 30],
            ['46119246', $secretList['rfc6238#sha256'], 'sha256', 8, new DateTime('1970-01-01 00:00:59'), 30],
            ['90693936', $secretList['rfc6238#sha512'], 'sha512', 8, new DateTime('1970-01-01 00:00:59'), 30],
            ['07081804', $secretList['rfc6238#sha1'],   'sha1',   8, new DateTime('2005-03-18 01:58:29'), 30],
            ['68084774', $secretList['rfc6238#sha256'], 'sha256', 8, new DateTime('2005-03-18 01:58:29'), 30],
            ['25091201', $secretList['rfc6238#sha512'], 'sha512', 8, new DateTime('2005-03-18 01:58:29'), 30],
            ['14050471', $secretList['rfc6238#sha1'],   'sha1',   8, new DateTime('2005-03-18 01:58:31'), 30],
            ['67062674', $secretList['rfc6238#sha256'], 'sha256', 8, new DateTime('2005-03-18 01:58:31'), 30],
            ['99943326', $secretList['rfc6238#sha512'], 'sha512', 8, new DateTime('2005-03-18 01:58:31'), 30],
            ['89005924', $secretList['rfc6238#sha1'],   'sha1',   8, new DateTime('2009-02-13 23:31:30'), 30],
            ['91819424', $secretList['rfc6238#sha256'], 'sha256', 8, new DateTime('2009-02-13 23:31:30'), 30],
            ['93441116', $secretList['rfc6238#sha512'], 'sha512', 8, new DateTime('2009-02-13 23:31:30'), 30],
            ['69279037', $secretList['rfc6238#sha1'],   'sha1',   8, new DateTime('2033-05-18 03:33:20'), 30],
            ['90698825', $secretList['rfc6238#sha256'], 'sha256', 8, new DateTime('2033-05-18 03:33:20'), 30],
            ['38618901', $secretList['rfc6238#sha512'], 'sha512', 8, new DateTime('2033-05-18 03:33:20'), 30],
            ['65353130', $secretList['rfc6238#sha1'],   'sha1',   8, new DateTime('2603-10-11 11:33:20'), 30],
            ['77737706', $secretList['rfc6238#sha256'], 'sha256', 8, new DateTime('2603-10-11 11:33:20'), 30],
            ['47863826', $secretList['rfc6238#sha512'], 'sha512', 8, new DateTime('2603-10-11 11:33:20'), 30],
        ];
    }

    /**
     * @dataProvider hotpTestVectors
     *
     * @param string $otpKey
     * @param string $otpSecret
     * @param string $otpHashAlgorithm
     * @param int    $otpDigits
     * @param int    $otpCounter
     */
    public function testHotp($otpKey, $otpSecret, $otpHashAlgorithm, $otpDigits, $otpCounter)
    {
        $frkOtp = new FrkOtp();
        $this->assertSame($otpKey, $frkOtp->hotp($otpSecret, $otpHashAlgorithm, $otpDigits, $otpCounter));
        $this->assertTrue($frkOtp->verifyHotp($otpKey, $otpSecret, $otpHashAlgorithm, $otpDigits, $otpCounter));
    }

    /**
     * @dataProvider totpTestVectors
     *
     * @param string    $otpKey
     * @param string    $otpSecret
     * @param string    $otpHashAlgorithm
     * @param int       $otpDigits
     * @param \DateTime $dateTime
     * @param int       $totpPeriod
     */
    public function testTotp($otpKey, $otpSecret, $otpHashAlgorithm, $otpDigits, DateTime $dateTime, $totpPeriod)
    {
        $frkOtp = new FrkOtp();
        $this->assertSame($otpKey, $frkOtp->totp($otpSecret, $otpHashAlgorithm, $otpDigits, $dateTime->getTimestamp(), $totpPeriod));
        $this->assertTrue($frkOtp->verifyTotp($otpKey, $otpSecret, $otpHashAlgorithm, $otpDigits, $dateTime->getTimestamp(), $totpPeriod));
    }

    public function testTotpWindow()
    {
        $frkOtp = new FrkOtp();

//        $this->assertSame('628637', $frkOtp->totp('12345678901234567890', 'sha1', 6, new DateTime('2018-01-01 08:00:00'), 30));
//        $this->assertSame('130937', $frkOtp->totp('12345678901234567890', 'sha1', 6, new DateTime('2018-01-01 07:59:30'), 30));
//        $this->assertSame('875993', $frkOtp->totp('12345678901234567890', 'sha1', 6, new DateTime('2018-01-01 08:00:30'), 30));
//        $this->assertSame('114787', $frkOtp->totp('12345678901234567890', 'sha1', 6, new DateTime('2018-01-01 08:01:00'), 30));
//        $this->assertSame('564860', $frkOtp->totp('12345678901234567890', 'sha1', 6, new DateTime('2018-01-01 07:59:00'), 30));

        // we only support window of size 1, i.e. only codes valid in the
        // previous 30 seconds, and codes valid in the next 30 seconds from
        // "now"
        $dateTime = new DateTime('2018-01-01 08:00:00');
        $this->assertTrue($frkOtp->verifyTotp('628637', '12345678901234567890', 'sha1', 6, $dateTime->getTimestamp(), 30));
        $this->assertTrue($frkOtp->verifyTotp('130937', '12345678901234567890', 'sha1', 6, $dateTime->getTimestamp(), 30));
        $this->assertTrue($frkOtp->verifyTotp('875993', '12345678901234567890', 'sha1', 6, $dateTime->getTimestamp(), 30));

        // codes outside this window are not supported
        $this->assertFalse($frkOtp->verifyTotp('114787', '12345678901234567890', 'sha1', 6, $dateTime->getTimestamp(), 30));
        $this->assertFalse($frkOtp->verifyTotp('564860', '12345678901234567890', 'sha1', 6, $dateTime->getTimestamp(), 30));
    }
}
