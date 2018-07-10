PHP library to verify TOTP codes and protect against replay and brute force 
attacks with support for PHP >= 5.4.

# Why

High quality TOTP verification libraries exist, e.g. 
[christian-riesen/otp](https://github.com/ChristianRiesen/otp) and 
[spomky-labs/otphp](https://github.com/Spomky-Labs/otphp) which are popular and
work well, however, they lack built-in support for protection against replay 
attacks and brute force attempts. The `spomky-labs/otphp` library would be a
good candidate, but only supports modern versions of PHP.

Another reason to build something myself was to have the ability to get rid of
any toggles. There is only one configuration.

# Features

* Supports PHP >= 5.4;
* Verifies TOTP codes;
* Protects againts replay attacks by storing the (used) TOTP keys;
* Protects against brute force attacks by limiting the number of attempts in 
  a time frame.
* Only supports one configuration:
  * period is always 30 seconds;
  * hash algorithm is always SHA1;
  * two period "drifts" are supported, i.e. the code valid in the previous 30 
    seconds and the code valid in the next 30 seconds;
  * only 6 digits are suppored.

# Inspiration

This library was inspired by other software, both in idea and sometimes code.
A list:

* [paragonie/sodium_compat](https://github.com/paragonie/sodium_compat) (ISC) for the `store64_be` function adapted from 
  the `store64_le` function;
* [christian-riesen/otp](https://github.com/ChristianRiesen/otp) (MIT) and 
  [spomky-labs/otphp](https://github.com/Spomky-Labs/otphp) (MIT), mostly for
  the ideas regarding accepting TOTP keys from the previous and next "period".

# License 

[MIT](LICENSE).
