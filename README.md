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

See `example/otp.php`.

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
