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

namespace fkooman\Otp;

use DateTime;
use ParagonIE\ConstantTime\Binary;
use RangeException;
use RuntimeException;

class FrkOtp implements OtpVerifierInterface
{
    /**
     * @param string $otpSecret
     * @param string $otpHashAlgorithm
     * @param int    $otpDigits
     * @param int    $otpCounter
     *
     * @return string
     */
    public static function hotp($otpSecret, $otpHashAlgorithm, $otpDigits, $otpCounter)
    {
        if (0 > $otpCounter) {
            throw new RangeException('counter must be >= 0');
        }
        if (!\in_array($otpHashAlgorithm, \hash_algos(), true)) {
            throw new RuntimeException(\sprintf('hash algorithm "%s" not supported', $otpHashAlgorithm));
        }
        if (!\in_array($otpDigits, [6, 7, 8], true)) {
            throw new RangeException('digits must be 6, 7 or 8');
        }
        $hashResult = \hash_hmac($otpHashAlgorithm, self::intToByteArray($otpCounter), $otpSecret, true);
        $hashOffset = \ord($hashResult[Binary::safeStrlen($hashResult) - 1]) & 0xf;
        $binaryCode = (\ord($hashResult[$hashOffset]) & 0x7f) << 24
            | (\ord($hashResult[$hashOffset + 1]) & 0xff) << 16
            | (\ord($hashResult[$hashOffset + 2]) & 0xff) << 8
            | (\ord($hashResult[$hashOffset + 3]) & 0xff);
        $otp = $binaryCode % \pow(10, $otpDigits);

        return \str_pad((string) $otp, $otpDigits, '0', STR_PAD_LEFT);
    }

    /**
     * @param string $otpKey
     * @param string $otpSecret
     * @param string $otpHashAlgorithm
     * @param int    $otpDigits
     * @param int    $otpCounter
     *
     * @return bool
     */
    public static function verifyHotp($otpKey, $otpSecret, $otpHashAlgorithm, $otpDigits, $otpCounter)
    {
        return \hash_equals(self::hotp($otpSecret, $otpHashAlgorithm, $otpDigits, $otpCounter), $otpKey);
    }

    /**
     * @param string    $otpSecret
     * @param string    $otpHashAlgorithm
     * @param int       $otpDigits
     * @param \DateTime $dateTime
     * @param int       $totpPeriod
     *
     * @return string
     */
    public static function totp($otpSecret, $otpHashAlgorithm, $otpDigits, DateTime $dateTime, $totpPeriod)
    {
        self::validatePeriod($totpPeriod);
        $totpTimestamp = $dateTime->getTimestamp();
        $otpCounter = (int) \floor($totpTimestamp / $totpPeriod);

        return self::hotp($otpSecret, $otpHashAlgorithm, $otpDigits, $otpCounter);
    }

    /**
     * @param string    $otpKey
     * @param string    $otpSecret
     * @param string    $otpHashAlgorithm
     * @param int       $otpDigits
     * @param \DateTime $dateTime
     * @param int       $totpPeriod
     *
     * @return bool
     */
    public static function verifyTotp($otpKey, $otpSecret, $otpHashAlgorithm, $otpDigits, DateTime $dateTime, $totpPeriod)
    {
        self::validatePeriod($totpPeriod);
        $totpTimestamp = $dateTime->getTimestamp();

        foreach ([0, -1, 1] as $totpWindow) {
            $otpCounter = (int) \floor(($totpTimestamp + $totpWindow * $totpPeriod) / $totpPeriod);
            // XXX replace this with self::totp!
            if (self::verifyHotp($otpKey, $otpSecret, $otpHashAlgorithm, $otpDigits, $otpCounter)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param int $int
     *
     * @return string
     */
    private static function intToByteArray($int)
    {
        if (8 !== PHP_INT_SIZE) {
            throw new RuntimeException('only 64 bit PHP installations are supported');
        }

        if (\PHP_VERSION_ID >= 50603) {
            return \pack('J', $int);
        }

        return \pack('C', ($int >> 56) & 0xff).
            \pack('C', ($int >> 48) & 0xff).
            \pack('C', ($int >> 40) & 0xff).
            \pack('C', ($int >> 32) & 0xff).
            \pack('C', ($int >> 24) & 0xff).
            \pack('C', ($int >> 16) & 0xff).
            \pack('C', ($int >> 8) & 0xff).
            \pack('C', ($int & 0xff));
    }

    /**
     * @param int $totpPeriod
     *
     * @return void
     */
    private static function validatePeriod($totpPeriod)
    {
        if (0 >= $totpPeriod) {
            throw new RangeException('period must be positive');
        }
    }
}
