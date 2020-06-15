<h1 align="center"> php-apple-signin </h1>

<p align="center"> PHP library to manage Sign In with Apple identifier tokens, and validate them server side passed through by the iOS client.</p>


## Installing

```shell
$ composer require jimchen/php-apple-signin -vvv
```

## Usage

```php

<?php
use JimChen\AppleSignIn\ASDecoder;

$clientUser = "example_client_user";
$identityToken = "example_encoded_jwt";

$appleSignInPayload = ASDecoder::getAppleSignInPayload($identityToken);

/**
 * Obtain the Sign In with Apple email and user creds.
 */
$email = $appleSignInPayload->getEmail();
$user = $appleSignInPayload->getUser();

/**
 * Determine whether the client-provided user is valid.
 */
$isValid = $appleSignInPayload->verifyUser($clientUser);

?>
```

## Contributing

You can contribute in one of three ways:

1. File bug reports using the [issue tracker](https://github.com/JimChenWYU/php-apple-signin/issues).
2. Answer questions or fix bugs on the [issue tracker](https://github.com/JimChenWYU/php-apple-signin/issues).
3. Contribute new features or update the wiki.

_The code contribution process is not very formal. You just need to make sure that you follow the PSR-0, PSR-1, and PSR-2 coding guidelines. Any new code contributions must be accompanied by unit tests where applicable._

## License

MIT