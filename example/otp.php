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

/** @psalm-suppress UnresolvableInclude */
require_once \sprintf('%s/vendor/autoload.php', \dirname(__DIR__));

use fkooman\Otp\Exception\OtpException;
use fkooman\Otp\FrkOtp;
use fkooman\Otp\Storage;
use fkooman\Otp\Totp;
use ParagonIE\ConstantTime\Base32;

$dateTime = new DateTime(); // now
$userId = 'foo';

/** @var string $otpSecret */
$otpSecret = Base32::encodeUpper(\random_bytes(20));
/** @var string $otpKey */
$otpKey = FrkOtp::totp(Base32::decodeUpper($otpSecret), 'sha1', 6, $dateTime, 30);

// init
$otpStorage = new Storage(new PDO('sqlite::memory:'));
$otpStorage->init();
$t = new Totp($otpStorage);
$t->register($userId, $otpSecret, $otpKey);

// we MUST get a new OTP key to do validation, as the OTP key used for the
// registration cannot be used again (replay protection). So, we generate the
// OTP key for 30 seconds in the future...
$dateTime->add(new DateInterval('PT30S'));

/** @var string $otpKey */
$otpKey = FrkOtp::totp(Base32::decodeUpper($otpSecret), 'sha1', 6, $dateTime, 30);

// verify the otpKey
if ($t->verify($userId, $otpKey)) {
    echo 'VALID!'.PHP_EOL;
} else {
    echo 'NOT VALID!'.PHP_EOL;
}

// replay the OTP key, this throws an OtpException as expected...
try {
    $t->verify($userId, $otpKey);
} catch (OtpException $e) {
    echo \sprintf('ERROR: %s', $e->getMessage()).PHP_EOL;
}

// try to brute force the OTP key...
try {
    $i = 0;
    while (true) {
        $t->verify($userId, (string) (123456 + $i));
        ++$i;
    }
} catch (OtpException $e) {
    echo \sprintf('ERROR: %s', $e->getMessage()).PHP_EOL;
}
