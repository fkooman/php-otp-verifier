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
use fkooman\Otp\FrkOtpVerifier;
use fkooman\Otp\Storage;
use fkooman\Otp\Totp;
use ParagonIE\ConstantTime\Base32;

$userId = 'foo';

// initialization
$otpStorage = new Storage(new PDO('sqlite::memory:'));
$otpStorage->init();
$t = new Totp($otpStorage, new FrkOtpVerifier());

/** @var string $otpSecret */
$otpSecret = Totp::generateSecret();

// obtain a valid otpKey for this secret at this moment
// NOTE: this is done by the user's OTP application, we do it here just to
// create a complete example!
/** @var string $otpKey */
$otpKey = FrkOtp::totp(Base32::decodeUpper($otpSecret));

// register the OTP
$t->register($userId, $otpSecret, $otpKey);

// we have to wait for to otpKey to be rotated, we need to wait at most 30
// seconds for the new window... We can't replay the OTP key used for
// registration...
echo \sprintf('We have to wait %d seconds for a new OTP key...', 30 - \time() % 30).PHP_EOL;
while (0 !== \time() % 30) {
    \sleep(1);
}
/** @var string $otpKey */
$otpKey = FrkOtp::totp(Base32::decodeUpper($otpSecret));

// verify the otpKey
if ($t->verify($userId, $otpKey)) {
    echo 'VALID!'.PHP_EOL;
} else {
    echo 'NOT VALID!'.PHP_EOL;
}

// replay the otpKey, this throws the OtpException
try {
    $t->verify($userId, $otpKey);
} catch (OtpException $e) {
    echo \sprintf('ERROR: %s', $e->getMessage().PHP_EOL);
}

// try too many times with wrong otpKey
try {
    $i = 0;
    while (true) {
        $t->verify($userId, (string) (123456 + $i));
        ++$i;
    }
} catch (OtpException $e) {
    echo \sprintf('ERROR: %s', $e->getMessage().PHP_EOL);
}
