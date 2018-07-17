PHP library to verify OTP codes and protect against replay and brute force 
attacks with support for PHP >= 5.4.

# What

This is a library that includes HOTP and TOTP verification and protection 
against replay and brute force attacks.

# Why

High quality OTP verification libraries exist, e.g. 
[christian-riesen/otp](https://github.com/ChristianRiesen/otp) and 
[spomky-labs/otphp](https://github.com/Spomky-Labs/otphp) which are popular and
work well, however, they lack built-in support for protection against replay 
attacks and brute force attempts.

We needed a library that works on PHP >= 5.4, with only 64 bit support. While
it would have been possible to use `christian-riesen/otp` I decided to write
my own minimal library with less than 100 NCLOC, `src/FrkOtp.php`.

# Features

* Supports PHP >= 5.4;
* Verifies HOTP and TOTP codes;
* Protects againts replay attacks by storing the (used) OTP keys;
* Protects against brute force attacks by limiting the number of attempts in 
  a certain time frame.

# API 

## Database 


```php
$storage = new Storage('sqlite:/path/to/otp.sqlite');
```

You can call `init()` on the `Storage` object to initialize the database, do
this only _once_ during application installation:

```php
$storage->init();
```

## Registration

The TOTP application will need to be configurated with the secret and generate
a valid OTP key before registration can succeed. Your application can for 
example generate an OTP secret, generate a QR code and allow the user to 
import that in their OTP application.

```php
$totp = new Totp($storage);
$userId = 'fkooman';
$otpSecret = 'H7ISMUHIREODCOONJUOPKJJ4HJCS2PUD';
$otpKey = '371427';
$totp->register($userId, $otpSecret, $otpKey);
```

## Verification

```php
$userId = 'fkooman';
$otpKey = '621029';
if ($totp->verify($userId, $otpKey)) {
    echo 'VALID!' . PHP_EOL;
} else {
    echo 'NOT VALID!' . PHP_EOL;
}
```

See `example/otp.php` for a more complete example.

**NOTE**: the `example/otp.php` script uses `FrkOtp` directly, but this MUST
not be done in your code, it is only for demonstration purposes! Stick to the
API as documented above!

# Inspiration

This library was inspired by other software, both in idea and sometimes code.
A list:

* [paragonie/sodium_compat](https://github.com/paragonie/sodium_compat) (ISC) 
for the `intToByteArray` method adapted from the `Util::store64_le` method;
* [christian-riesen/otp](https://github.com/ChristianRiesen/otp) (MIT) and 
  [spomky-labs/otphp](https://github.com/Spomky-Labs/otphp) (MIT), mostly for
  the ideas regarding accepting TOTP keys from the previous and next time 
  window.

# License 

[MIT](LICENSE).
