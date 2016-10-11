# Ride: Security OAuth

OAuth implementation for the security library of the PHP Ride framework.

This security model is file based and usefull for a small user base.

## What's In This Library

### OAuth2Authenticator

The _OAuth2Authenticator_ implements the _Authenticator_ interface to make authentication through OAuth2 possible.

### ConnectPolicy

The _ConnectPolicy_ interface is used to automatically create users when they try to authenticate themselves for the first time.

#### EverybodyConnectPolicy

You can use the _EverybodyConnectPolicy_ to let everybody create a user in your security model.
This is usefull for a public application which needs a user to work properly

#### EmailConnectPolicy

The _EmailConnectPolicy_ can be used to create users when they have an email address provided. 
You can easily extends this class to match domains or to add roles to the user.

### OAuth2Client

The _OAuth2Client_ class is an extended HTTP client used to talk with the OAuth service.

This is implemented for Google and Facebook but other providers can be added easily.

### Related Modules

You can check the following related modules of this library:
- [ride/cli-security](https://github.com/all-ride/ride-cli-security)
- [ride/lib-security](https://github.com/all-ride/ride-lib-security)
- [ride/lib-security-generic](https://github.com/all-ride/ride-lib-security-generic)
- [ride/web-security-generic](https://github.com/all-ride/ride-web-security-generic)

## Installation

You can use [Composer](http://getcomposer.org) to install this library.

```
composer require ride/lib-security-oauth
```
