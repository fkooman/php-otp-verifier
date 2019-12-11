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
use PDO;

class Storage implements OtpStorageInterface
{
    /** @var \PDO */
    private $dbh;

    public function __construct(PDO $dbh)
    {
        $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $dbh->exec('PRAGMA foreign_keys = ON');
        $this->dbh = $dbh;
    }

    /**
     * @param string $userId
     *
     * @return false|OtpInfo
     */
    public function getOtpSecret($userId)
    {
        $stmt = $this->dbh->prepare('SELECT otp_secret, otp_hash_algorithm, otp_digits, totp_period FROM otp WHERE user_id = :user_id');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        /** @var false|array<string, string|int> */
        $otpInfo = $stmt->fetch(PDO::FETCH_ASSOC);
        if (false === $otpInfo) {
            return false;
        }

        return new OtpInfo(
            (string) $otpInfo['otp_secret'],
            (string) $otpInfo['otp_hash_algorithm'],
            (int) $otpInfo['otp_digits'],
            (int) $otpInfo['totp_period']
        );
    }

    /**
     * @param string $userId
     *
     * @return void
     */
    public function setOtpSecret($userId, OtpInfo $otpInfo)
    {
        $stmt = $this->dbh->prepare('INSERT INTO otp (user_id, otp_secret, otp_hash_algorithm, otp_digits, totp_period) VALUES(:user_id, :otp_secret, :otp_hash_algorithm, :otp_digits, :totp_period)');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':otp_secret', $otpInfo->getSecret(), PDO::PARAM_STR);
        $stmt->bindValue(':otp_hash_algorithm', $otpInfo->getHashAlgorithm(), PDO::PARAM_STR);
        $stmt->bindValue(':otp_digits', $otpInfo->getDigits(), PDO::PARAM_INT);
        $stmt->bindValue(':totp_period', $otpInfo->getPeriod(), PDO::PARAM_INT);

        $stmt->execute();
    }

    /**
     * @param string $userId
     *
     * @return void
     */
    public function deleteOtpSecret($userId)
    {
        $stmt = $this->dbh->prepare('DELETE FROM otp WHERE user_id = :user_id');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();
    }

    /**
     * @param string $userId
     *
     * @return int
     */
    public function getOtpAttemptCount($userId)
    {
        $stmt = $this->dbh->prepare('SELECT COUNT(*) FROM otp_log WHERE user_id = :user_id');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        return (int) $stmt->fetchColumn();
    }

    /**
     * @param string $userId
     * @param string $otpKey
     *
     * @return bool
     */
    public function recordOtpKey($userId, $otpKey, DateTime $dateTime)
    {
        // check if this user used the key before
        $stmt = $this->dbh->prepare('SELECT COUNT(*) FROM otp_log WHERE user_id = :user_id AND otp_key = :otp_key');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':otp_key', $otpKey, PDO::PARAM_STR);
        $stmt->execute();
        if (0 !== (int) $stmt->fetchColumn()) {
            return false;
        }

        // because the insert MUST succeed we avoid race condition where
        // potentially two times the same key for the same user are accepted,
        // we'd just get a PDOException because the UNIQUE(user_id, otp_key)
        // constrained is violated
        $stmt = $this->dbh->prepare('INSERT INTO otp_log (user_id, otp_key, date_time) VALUES (:user_id, :otp_key, :date_time)');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':otp_key', $otpKey, PDO::PARAM_STR);
        $stmt->bindValue(':date_time', $dateTime->format('Y-m-d H:i:s'), PDO::PARAM_STR);
        $stmt->execute();

        return true;
    }

    /**
     * @return void
     */
    public function cleanOtpLog(DateTime $dateTime)
    {
        $stmt = $this->dbh->prepare('DELETE FROM otp_log WHERE date_time < :date_time');
        $stmt->bindValue(':date_time', $dateTime->format('Y-m-d H:i:s'), PDO::PARAM_STR);

        $stmt->execute();
    }

    /**
     * @return void
     */
    public function init()
    {
        $this->dbh->exec(
<<<'EOT'
CREATE TABLE otp(
  user_id VARCHAR(255) NOT NULL PRIMARY KEY UNIQUE,
  otp_secret VARCHAR(255) NOT NULL,
  otp_hash_algorithm VARCHAR(255) NOT NULL,
  otp_digits INTEGER NOT NULL,
  totp_period INTEGER NOT NULL
)
EOT
        );
        $this->dbh->exec(
<<<'EOT'
CREATE TABLE otp_log(
  user_id VARCHAR(255) NOT NULL,
  otp_key VARCHAR(255) NOT NULL,
  date_time DATETIME NOT NULL,
  UNIQUE(user_id, otp_key)
)
EOT
        );
    }
}
