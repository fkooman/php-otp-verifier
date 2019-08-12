# Changelog

## 0.3.1 (...)
- fix URL encoding of OTP label for QR code

## 0.3.0 (2019-08-11)
- always throw `OtpException` when OTP verification fails instead of `bool` 
  return value

## 0.2.1 (2018-10-20)
- restore 32 bit PHP support

## 0.2.0 (2018-07-20)
- simplified API
- remove obsolete code
- remove a lot of abstractions
- store used hash algorithm, number of digits and TOTP period in database
- document API in README
- removed example

## 0.1.1 (2018-07-16)
- code cleanups
- more strict `vimeo/psalm` config file
- input validation on `FrkOtp` methods to check if parameters are supported
- fix example

## 0.1.0 (2018-07-12)
- intitial release
