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
use fkooman\Otp\Exception\OtpException;
use fkooman\Otp\Storage;
use fkooman\Otp\Totp;
use ParagonIE\ConstantTime\Base32;
use PDO;
use PHPUnit\Framework\TestCase;

class TotpTest extends TestCase
{
    /** @var Totp */
    private $totp;

    public function setUp()
    {
        $storage = new Storage(
            new PDO('sqlite::memory:')
        );
        $storage->init();

        $dateTime = new DateTime('2018-01-01 08:00:00');
        $this->totp = new Totp(
            $storage,
            new TestVerifier(),
            $dateTime
        );
        $this->totp->register('foo', Base32::encodeUpper('12345678901234567890'), '123456');
    }

    public function testVerifyFail()
    {
        try {
            $this->totp->verify('foo', '999999');
            $this->fail();
        } catch (OtpException $e) {
            $this->assertSame('invalid OTP code', $e->getMessage());
        }
    }

    public function testReplay()
    {
        $this->totp->verify('foo', '654321');
        try {
            $this->totp->verify('foo', '654321');
            $this->fail();
        } catch (OtpException $e) {
            $this->assertSame('replay of OTP code', $e->getMessage());
        }
    }

    public function testTooManyAttempt()
    {
        for ($i = 0; $i < 59; ++$i) {
            try {
                $this->totp->verify(
                    'foo',
                    \sprintf('%s', 234567 + $i)
                );
            } catch (OtpException $e) {
                $this->assertSame('invalid OTP code', $e->getMessage());
            }
        }

        try {
            $this->totp->verify('foo', '555555');
            $this->fail();
        } catch (OtpException $e) {
            $this->assertSame('too many attempts', $e->getMessage());
        }
    }

    public function testGetEnrollmentUri()
    {
        $this->assertSame(
            'otpauth://totp/My%20Service%20Inc.:foo%40example.org?secret=H7ISMUHIREODCOONJUOPKJJ4HJCS2PUD&algorithm=SHA1&digits=6&period=30&issuer=My%20Service%20Inc.',
            $this->totp->getEnrollmentUri('foo@example.org', 'H7ISMUHIREODCOONJUOPKJJ4HJCS2PUD', 'My Service Inc.')
        );
    }

    public function testGetEnrollmentUriColon()
    {
        $this->assertSame(
            'otpauth://totp/vpn.tuxed.net:https_%2F%2Fidp.tuxed.net%2Fmetadata%21https_%2F%2Fvpn.tuxed.net%2Fvpn-user-portal%2F_saml%2Fmetadata%21g1Bd2dM7ugdEVZlpKBoWUCL3GWc4LdewUW1YkgUnVEg%0A?secret=H7ISMUHIREODCOONJUOPKJJ4HJCS2PUD&algorithm=SHA1&digits=6&period=30&issuer=vpn.tuxed.net',
            $this->totp->getEnrollmentUri('https://idp.tuxed.net/metadata!https://vpn.tuxed.net/vpn-user-portal/_saml/metadata!g1Bd2dM7ugdEVZlpKBoWUCL3GWc4LdewUW1YkgUnVEg
', 'H7ISMUHIREODCOONJUOPKJJ4HJCS2PUD', 'vpn.tuxed.net')
        );
    }

    public function testGenerateSecret()
    {
        $this->assertSame(32, \strlen(Totp::generateSecret()));
    }
}
