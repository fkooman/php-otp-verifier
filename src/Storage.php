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
use PDO;
use PDOException;

class Storage implements TotpStorageInterface
{
    /** @var \PDO */
    private $dbh;

    /**
     * @param \PDO $dbh
     */
    public function __construct(PDO $dbh)
    {
        $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $dbh->exec('PRAGMA foreign_keys = ON');
        $this->dbh = $dbh;
    }

    /**
     * @param string $userId
     *
     * @return false|string
     */
    public function getTotpSecret($userId)
    {
        $stmt = $this->dbh->prepare('SELECT secret FROM totp WHERE user_id = :user_id');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetchColumn();
    }

    /**
     * @param string $userId
     * @param string $secret
     *
     * @return void
     */
    public function setTotpSecret($userId, $secret)
    {
        $stmt = $this->dbh->prepare('INSERT INTO totp (user_id, secret) VALUES(:user_id, :secret)');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':secret', $secret, PDO::PARAM_STR);
        $stmt->execute();
    }

    /**
     * @param string $userId
     *
     * @return void
     */
    public function deleteTotpSecret($userId)
    {
        $stmt = $this->dbh->prepare('DELETE FROM totp WHERE user_id = :user_id');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();
    }

    /**
     * @param string $userId
     *
     * @return int
     */
    public function getTotpAttemptCount($userId)
    {
        $stmt = $this->dbh->prepare('SELECT COUNT(*) FROM totp_log WHERE user_id = :user_id');
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        return (int) $stmt->fetchColumn();
    }

    /**
     * @param string    $userId
     * @param string    $totpKey
     * @param \DateTime $dateTime
     *
     * @return bool
     */
    public function recordTotpKey($userId, $totpKey, DateTime $dateTime)
    {
        try {
            $stmt = $this->dbh->prepare('INSERT INTO totp_log (user_id, totp_key, date_time) VALUES (:user_id, :totp_key, :date_time)');
            $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
            $stmt->bindValue(':totp_key', $totpKey, PDO::PARAM_STR);
            $stmt->bindValue(':date_time', $dateTime->format('Y-m-d H:i:s'), PDO::PARAM_STR);
            $stmt->execute();

            return true;
        } catch (PDOException $e) {
            return false;
        }
    }

    /**
     * @param \DateTime $dateTime
     *
     * @return void
     */
    public function cleanTotpLog(DateTime $dateTime)
    {
        $stmt = $this->dbh->prepare('DELETE FROM totp_log WHERE date_time < :date_time');
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
CREATE TABLE totp(
  user_id VARCHAR(255) NOT NULL PRIMARY KEY UNIQUE,
  secret VARCHAR(255) NOT NULL
)
EOT
        );
        $this->dbh->exec(
<<<'EOT'
CREATE TABLE totp_log(
  user_id VARCHAR(255) NOT NULL REFERENCES totp(user_id) ON DELETE CASCADE,
  totp_key VARCHAR(255) NOT NULL,
  date_time DATETIME NOT NULL,
  UNIQUE(user_id, totp_key)
)
EOT
        );
    }
}
