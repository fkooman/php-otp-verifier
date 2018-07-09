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

namespace fkooman\Totp;

use DateTime;
use fkooman\Totp\Exception\TotpException;
use ParagonIE\ConstantTime\Base32;

class Totp
{
    const ALGORITHM = 'sha1';
    const DIGITS = 6;
    const PERIOD = 30;
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
     * @return void
     */
    public function register($userId)
    {
        $totpSecret = Base32::encodeUpper($this->random->get(self::SECRET_SIZE_BYTES));
        $this->storage->setTotpSecret($userId, $totpSecret, self::ALGORITHM, self::DIGITS, self::PERIOD);
    }

    /**
     * @param string $userId
     * @param string $totpKey
     *
     * @return bool
     */
    public function verify($userId, $totpKey)
    {
        if (false === $totp = $this->storage->getTotpSecret($userId)) {
            throw new TotpException('user has no TOTP secret');
        }

        // store the attempt even before validating it, to be able to count
        // the (failed) attempts and also replay attacks
        if (false === $this->storage->recordTotpKey($userId, $totpKey, $this->dateTime)) {
            throw new TotpException('replay of TOTP code');
        }

        if (60 < $this->storage->getTotpAttemptCount($userId)) {
            throw new TotpException('too many attempts at TOTP');
        }

        return $this->otpVerifier->verify(Base32::decodeUpper($totp['secret']), $totpKey);
    }
}
