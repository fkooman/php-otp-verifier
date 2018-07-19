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
use fkooman\Otp\Exception\OtpException;
use ParagonIE\ConstantTime\Base32;

class Totp
{
    const OTP_MAX_ATTEMPT_COUNT = 60;

    /** @var OtpStorageInterface */
    private $storage;

    /** @var OtpVerifierInterface */
    private $otpVerifier;

    /** @var \DateTime */
    private $dateTime;

    /** @var string */
    private $otpAlgorithm = 'sha1';

    /** @var int */
    private $otpDigits = 6;

    /** @var int */
    private $totpPeriod = 30;

    /**
     * @param OtpStorageInterface       $storage
     * @param null|OtpVerifierInterface $otpVerifier
     * @param null|\DateTime            $dateTime
     */
    public function __construct(OtpStorageInterface $storage, OtpVerifierInterface $otpVerifier = null, DateTime $dateTime = null)
    {
        $this->storage = $storage;
        if (null === $otpVerifier) {
            $otpVerifier = new FrkOtp();
        }
        $this->otpVerifier = $otpVerifier;
        if (null === $dateTime) {
            $dateTime = new DateTime();
        }
        $this->dateTime = $dateTime;
    }

    /**
     * @param string $userId
     * @param string $otpSecret
     * @param string $otpIssuer
     *
     * @return string
     */
    public function getEnrollmentUri($userId, $otpSecret, $otpIssuer)
    {
        $otpLabel = \sprintf('%s:%s', \rawurlencode($otpIssuer), \rawurlencode($userId));

        return \sprintf(
            'otpauth://totp/%s?secret=%s&algorithm=%s&digits=%d&period=%d&issuer=%s',
            $otpLabel,
            $otpSecret,
            \strtoupper($this->otpAlgorithm),
            $this->otpDigits,
            $this->totpPeriod,
            \rawurlencode($otpIssuer)
        );
    }

    /**
     * @return string
     */
    public static function generateSecret()
    {
        return Base32::encodeUpper(\random_bytes(20));
    }

    /**
     * @param string $userId
     * @param string $otpSecret
     * @param string $otpKey
     *
     * @return void
     */
    public function register($userId, $otpSecret, $otpKey)
    {
        if (false !== $this->storage->getOtpSecret($userId)) {
            throw new OtpException(\sprintf('user "%s" already has an OTP secret', $userId));
        }

        if (false === $this->verifyWithSecret($userId, $otpSecret, $otpKey)) {
            throw new OtpException('invalid OTP code');
        }

        $this->storage->setOtpSecret($userId, $otpSecret);
    }

    /**
     * @param string $userId
     * @param string $otpKey
     *
     * @return bool
     */
    public function verify($userId, $otpKey)
    {
        if (false === $otpSecret = $this->storage->getOtpSecret($userId)) {
            throw new OtpException(\sprintf('user "%s" has no OTP secret', $userId));
        }

        return $this->verifyWithSecret($userId, $otpSecret, $otpKey);
    }

    /**
     * @param string $otpAlgorithm
     *
     * @return void
     */
    public function setAlgorithm($otpAlgorithm)
    {
        $this->otpAlgorithm = $otpAlgorithm;
    }

    /**
     * @param int $otpDigits
     *
     * @return void
     */
    public function setDigits($otpDigits)
    {
        $this->otpDigits = $otpDigits;
    }

    /**
     * @param int $totpPeriod
     *
     * @return void
     */
    public function setParameters($totpPeriod)
    {
        $this->totpPeriod = $totpPeriod;
    }

    /**
     * @param string $userId
     * @param string $otpSecret
     * @param string $otpKey
     *
     * @return bool
     */
    private function verifyWithSecret($userId, $otpSecret, $otpKey)
    {
        // store the attempt even before validating it, to be able to count
        // the (failed) attempts and also replay attacks
        if (false === $this->storage->recordOtpKey($userId, $otpKey, $this->dateTime)) {
            throw new OtpException('replay of OTP code');
        }

        if (self::OTP_MAX_ATTEMPT_COUNT < $this->storage->getOtpAttemptCount($userId)) {
            throw new OtpException('too many attempts');
        }

        return $this->otpVerifier->verifyTotp(
            $otpKey,
            Base32::decodeUpper($otpSecret),
            $this->otpAlgorithm,
            $this->otpDigits,
            $this->dateTime->getTimestamp(),
            $this->totpPeriod
        );
    }
}
