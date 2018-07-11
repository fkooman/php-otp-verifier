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
    const SECRET_SIZE_BYTES = 20;    // 160 bits

    /** @var Storage */
    private $storage;

    /** @var OtpVerifierInterface */
    private $otpVerifier;

    /** @var \DateTime */
    private $dateTime;

    /** @var RandomInterface */
    private $random;

    /**
     * @param Storage              $storage
     * @param OtpVerifierInterface $otpVerifier
     */
    public function __construct(Storage $storage, OtpVerifierInterface $otpVerifier)
    {
        $this->storage = $storage;
        $this->otpVerifier = $otpVerifier;
        $this->dateTime = new DateTime();
        $this->random = new Random();
    }

    /**
     * @param \DateTime $dateTime
     *
     * @return void
     */
    public function setDateTime(DateTime $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * @param RandomInterface $random
     *
     * @return void
     */
    public function setRandom(RandomInterface $random)
    {
        $this->random = $random;
    }

    /**
     * @param string $userId
     *
     * @return string
     */
    public function register($userId)
    {
        if (false !== $this->storage->getOtpSecret($userId)) {
            throw new OtpException(\sprintf('user "%s" already has an OTP secret', $userId));
        }
        $otpSecret = Base32::encodeUpper($this->random->get(self::SECRET_SIZE_BYTES));
        $this->storage->setOtpSecret($userId, $otpSecret);

        return $otpSecret;
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
