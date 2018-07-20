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

class OtpInfo
{
    /** @var string */
    private $otpSecret;

    /** @var string */
    private $otpHashAlgorithm;

    /** @var int */
    private $otpDigits;

    /** @var int */
    private $totpPeriod;

    /**
     * @param string $otpSecret
     * @param string $otpHashAlgorithm
     * @param int    $otpDigits
     * @param int    $totpPeriod
     */
    public function __construct($otpSecret, $otpHashAlgorithm, $otpDigits, $totpPeriod)
    {
        $this->otpSecret = $otpSecret;
        $this->otpHashAlgorithm = $otpHashAlgorithm;
        $this->otpDigits = $otpDigits;
        $this->totpPeriod = $totpPeriod;
    }

    /**
     * @return string
     */
    public function getSecret()
    {
        return $this->otpSecret;
    }

    /**
     * @return string
     */
    public function getHashAlgorithm()
    {
        return $this->otpHashAlgorithm;
    }

    /**
     * @return int
     */
    public function getDigits()
    {
        return $this->otpDigits;
    }

    /**
     * @return int
     */
    public function getPeriod()
    {
        return $this->totpPeriod;
    }
}
