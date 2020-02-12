PHP library to verify OTP codes and protect against replay and brute force 
attacks with support for PHP >= 5.4.

# What

This is a library that includes TOTP verification and protection against replay 
and brute force attacks. In the future HOTP may be supported as well.

# Why

High quality OTP verification libraries exist, e.g. 
[christian-riesen/otp](https://github.com/ChristianRiesen/otp) and 
[spomky-labs/otphp](https://github.com/Spomky-Labs/otphp) which are popular and
work well, however, they lack built-in support for protection against replay 
attacks and brute force attempts.

We needed a library that works on PHP >= 5.4. While it would have been possible 
to use `christian-riesen/otp` I decided to write my own minimal library with 
less than 100 NCLOC, `src/FrkOtp.php`.

# Features

* Supports PHP >= 5.4;
* Verifies TOTP codes;
* Protects againts replay attacks by storing the (used) OTP keys;
* Protects against brute force attacks by limiting the number of attempts in 
  a certain time frame.

# API 

## Database 

A database is needed to store OTP secrets and used OTP keys. Currently only
SQLite is tested, but others may work.

```php
    $storage = new fkooman\Otp\Storage(new PDO('sqlite:/path/to/db.sqlite'));
```

You can call `init()` on the `Storage` object to initialize the database, do
this only _once_, during application installation:

```php
    $storage->init();
```

## Settings

The default TOTP configuration is:

* Use `SHA1` as hash;
* Use 6 digits;
* Use a 30 second "period" in which the OTP keys are valid.

You can modify these by calling the respective methods:

```php
    $totp = new fkooman\Otp\Totp($storage);
    $totp->setHashAlgorithm('sha256');
    $totp->setDigits(8);
    $totp->setPeriod(15);
```

Not all OTP clients will support all options. The _default_ options work 
everywhere I tested. Google Authenticator ONLY works with the defaults.

## Registration

The TOTP application will need to be configurated with the secret and generate
a valid OTP key before registration can succeed. Your application can for 
example generate an OTP secret, generate a QR code and allow the user to 
import that in their OTP application.

```php
    $otpSecret = fkooman\Otp\Totp::generateSecret();
```

Most (T)OTP applications can handle a QR code for enrollment, making it much
easier for users to configure their application. This library can generate a 
[Key-URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) 
to make this easier with all the right parameters set:

```php
    $totp = new fkooman\Otp\Totp($storage);
    $userId = 'foo@example.org';
    $totp->getEnrollmentUri($userId, $otpSecret, 'My Service Inc.');
```

This will return something like this: `otpauth://totp/foo%40example.org:My%20Service%20Inc.?secret=H7ISMUHIREODCOONJUOPKJJ4HJCS2PUD&algorithm=SHA1&digits=8&period=10&issuer=My%20Service%20Inc.`

Use this URI in a QR code and show it to the user. Once you get back a valid 
OTP key from the user, e.g. entered in a form, you can complete the 
registration:

```php
    $userId = 'fkooman';
    $otpSecret = 'H7ISMUHIREODCOONJUOPKJJ4HJCS2PUD';
    // make sure the OTP key is freshly generated by a TOTP app!
    $otpKey = '371427';
    $totp->register($userId, $otpSecret, $otpKey);
```

The `fkooman\Otp\Totp::register` method will throw an 
`fkooman\Otp\OtpException` if registration failed.

## Verification

A `boolean` is returned indicating the OTP key was valid for the configured
OTP secret.

```php
    $userId = 'fkooman';
    // make sure the OTP key is freshly generated by a TOTP app!
    $otpKey = '621029';
    try {
        $totp->verify($userId, $otpKey);
        echo 'VALID';
    } catch (fkooman\Otp\OtpException $e) {
        echo 'NOT VALID: '.$e->getMessage();
    }
```

**NOTE**: you can not reuse the OTP key used for registration for verification
afterwards. You have to wait for the next window.

The `fkooman\Otp\Totp::verify` method will throw an `fkooman\Otp\OtpException`, 
when the provided user has no OTP secret, when the OTP code is invalid, the OTP 
code is replayed, or when the limit of verifications was reached.

# Inspiration

This library was inspired by other software, both in idea and sometimes code.
A list:

* [paragonie/sodium_compat](https://github.com/paragonie/sodium_compat) (ISC) 
for the `intToByteArray` method adapted from the `Util::store64_le` method;
* [christian-riesen/otp](https://github.com/ChristianRiesen/otp) (MIT) and 
  [spomky-labs/otphp](https://github.com/Spomky-Labs/otphp) (MIT), mostly for
  the ideas regarding accepting TOTP keys from the previous and next time 
  window(s).

# License 

[MIT](LICENSE).
