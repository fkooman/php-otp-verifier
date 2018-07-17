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
use fkooman\Otp\OtpVerifierInterface;

class TestVerifier implements OtpVerifierInterface
{
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
        if ('123456' === $otpKey || '654321' === $otpKey) {
            return true;
        }

        return false;
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
        return '987654';
    }
}
