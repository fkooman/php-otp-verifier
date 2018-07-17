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
    /** @var OtpStorageInterface */
    private $storage;

    /** @var OtpVerifierInterface */
    private $otpVerifier;

    /** @var \DateTime */
    private $dateTime;

    /**
     * @param OtpStorageInterface       $storage
     * @param null|\DateTime            $dateTime
     * @param null|OtpVerifierInterface $otpVerifier
     */
    public function __construct(OtpStorageInterface $storage, DateTime $dateTime = null, OtpVerifierInterface $otpVerifier = null)
    {
        $this->storage = $storage;
        if (null === $dateTime) {
            $dateTime = new DateTime();
        }
        $this->dateTime = $dateTime;
        if (null === $otpVerifier) {
            $otpVerifier = new FrkOtpVerifier($dateTime);
        }
        $this->otpVerifier = $otpVerifier;
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

        if (60 < $this->storage->getOtpAttemptCount($userId)) {
            throw new OtpException('too many attempts at OTP');
        }

        return $this->otpVerifier->verify(Base32::decodeUpper($otpSecret), $otpKey);
    }
}
