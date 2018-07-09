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

interface TotpStorageInterface
{
    /**
     * @param string $userId
     *
     * @return false|array<string, string>
     */
    public function getTotpSecret($userId);

    /**
     * @param string $userId
     * @param string $secret
     * @param string $algorithm
     * @param int    $digits
     * @param int    $period
     *
     * @return bool
     */
    public function setTotpSecret($userId, $secret, $algorithm, $digits, $period);

    /**
     * @param string $userId
     *
     * @return void
     */
    public function deleteTotpSecret($userId);

    /**
     * @param string $userId
     *
     * @return int
     */
    public function getTotpAttemptCount($userId);

    /**
     * @param string    $userId
     * @param string    $totpKey
     * @param \DateTime $dateTime
     *
     * @return bool
     */
    public function recordTotpKey($userId, $totpKey, DateTime $dateTime);

    /**
     * @param \DateTime $dateTime
     *
     * @return void
     */
    public function cleanTotpLog(DateTime $dateTime);
}
