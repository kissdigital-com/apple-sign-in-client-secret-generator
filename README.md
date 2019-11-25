# Apple Signin Client Secret Generator for php
![KISSDIGITALCOM](https://kiss.home.pl/github/apple-sign-in-client-secret-generator-logo-kissdigital.png)

## Description
This package provides class that generates token derived from your private key using ES256 JWT algorithm. For more info check [useful links](#useful-links) 

## Requirements

PHP 7.2+

## Installation

Install the composer package:

```composer require kissdigital-com/apple-sign-in-client-secret-generator```

## Example Usage

```php
<?php

use Kissdigitalcom\AppleSignIn\ClientSecret;

$clientId = 'com.kissdigital.TESTAPP';
$teamId   = 'FOO123BAR456';
$keyId    = '654RAB321OOF';
$certPath = __DIR__ . '/certificate.p8';

$clientSecret = new ClientSecret($clientId, $teamId, $keyId, $certPath);

echo $clientSecret->generate();

```

## Useful links

* [https://developer.apple.com/sign-in-with-apple/get-started](https://developer.apple.com/sign-in-with-apple/get-started)
* [https://developer.okta.com/blog/2019/06/04/what-the-heck-is-sign-in-with-apple](https://developer.okta.com/blog/2019/06/04/what-the-heck-is-sign-in-with-apple)

## About KISS digital
KISS digital is a digital agency located in Kraków, Poland. We provide creative, strategic and technical development of websites and mobile applications.