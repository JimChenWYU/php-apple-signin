<?php

namespace JimChen\AppleSignIn;

use DateTime;
use DomainException;
use InvalidArgumentException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Parsing\Decoder;
use ReflectionClass;
use UnexpectedValueException;

class JWT
{
    /**
     * The server leeway time in seconds, to aware the acceptable different time between clocks
     * of token issued server and relying parties.
     * When checking nbf, iat or expiration times, we want to provide some extra leeway time to
     * account for clock skew.
     */
    public static $leeway = 0;

    public static $supported_algs = array(
        'HS512' => \Lcobucci\JWT\Signer\Hmac\Sha512::class,
        'HS256' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
        'HS384' => \Lcobucci\JWT\Signer\Hmac\Sha384::class,
        'RS512' => \Lcobucci\JWT\Signer\Rsa\Sha512::class,
        'RS256' => \Lcobucci\JWT\Signer\Rsa\Sha256::class,
        'RS384' => \Lcobucci\JWT\Signer\Rsa\Sha384::class,
    );

    /**
     * @param string $jwt
     * @return mixed
     */
    public static function getPublicKeyKid(string $jwt)
    {
        $token = (new Parser)->parse($jwt);
        return $token->getHeader('kid');
    }

    /**
     * Decodes a JWT string into a PHP object.
     */
    public static function decode(string $jwt, string $key, array $allowed_algs = [])
    {
        $timestamp = time();
        $token = (new Parser)->parse($jwt);
        $alg = $token->getHeader('alg');
        if (empty($key)) {
            throw new InvalidArgumentException('Key may not be empty');
        }
        if (empty($alg)) {
            throw new UnexpectedValueException('Empty algorithm');
        }
        if (!in_array($alg, $allowed_algs)) {
            throw new UnexpectedValueException('Algorithm not allowed');
        }
        if (empty(static::$supported_algs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }
        /** @var \Lcobucci\JWT\Signer $signer */
        $reflection = new ReflectionClass(static::$supported_algs[$alg]);
        $signer = $reflection->newInstance();
        if (!$token->verify($signer, $key)) {
            throw new SignatureInvalidException('Signature verification failed');
        }
        // Check if the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if ($token->hasClaim('nbf')) {
            $nbf = $token->getClaim('nbf');
            if (isset($nbf) && $nbf > ($timestamp + static::$leeway)) {
                throw new BeforeValidException(
                    'Cannot handle token prior to ' . date(DateTime::ATOM, $nbf)
                );
            }
        }
        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if ($token->hasClaim('iat')) {
            $iat = $token->getClaim('iat');
            if (isset($iat) && $iat > ($timestamp + static::$leeway)) {
                throw new BeforeValidException(
                    'Cannot handle token prior to ' . date(DateTime::ATOM, $iat)
                );
            }
        }
        // Check if this token has expired.
        if ($token->hasClaim('exp')) {
            $exp = $token->getClaim('exp');
            if (isset($exp) && ($timestamp - static::$leeway) >= $exp) {
                throw new ExpiredException('Expired token');
            }
        }

        return (object)$token->getClaims();
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public static function urlsafeB64Decode(string $input)
    {
        return (new Decoder)->base64UrlDecode($input);
    }
}
