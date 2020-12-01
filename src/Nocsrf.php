<?php

declare(strict_types=1);

namespace jblond;

use Exception;

/**
 * NoCSRF, an anti CSRF token generation/checking class.
 *
 * @author Thibaut Despoulain <http://bkcore.com>
 * @author Mario Brandt
 * @version 1.6
 */
class Nocsrf
{

    /**
     * @var bool $doOriginCheck
     */
    protected $doOriginCheck = false;

    /**
     * @var bool
     */
    protected $noError = true;

    /**
     * Check CSRF tokens match between session and $origin.
     * Make sure you generated a token in the form before checking it.
     *
     * @param string $key The session and $origin key where to find the token.
     * @param array $origin The object/associative array to retrieve the token data from (usually $_POST).
     * @param bool $throwException (optional) TRUE to throw exception on check fail, FALSE or default to return false
     * @param int|null $time_span (optional) Makes the token expire after $time_span seconds. (null = never)
     * @param bool $multiple (optional) Makes the token reusable and not one-time. (Useful for ajax-heavy requests).
     *
     * @throws Exception
     * @return bool Returns FALSE if a CSRF attack is detected, TRUE otherwise.
     */
    public function check(
        string $key,
        array $origin,
        bool $throwException = false,
        ?int $time_span = null,
        bool $multiple = false
    ): bool {
        $this->isCsfrMissing($key, $throwException);
        $this->isFormTokenSet($origin, $key, $throwException);



        // Get valid token from session
        $hash = $_SESSION['csrf_' . $key];

        // Free up session token for one-time CSRF token usage.
        if (!$multiple) {
            $_SESSION['csrf_' . $key] = null;
        }

        $this->isHashOkay($hash, $throwException);
        $this->doesTokenMatch($origin, $key, $hash, $throwException);
        $this->isTokenExpired($time_span, $hash, $throwException);

        if ($this->noError === false) {
            return false;
        }
        return true;
    }

    /**
     * Adds extra user agent and remote_address checks to CSRF protections.
     * @return void
     */
    public function enableOriginCheck(): void
    {
        $this->doOriginCheck = true;
    }

    /**
     * CSRF token generation method. After generating the token, put it inside a hidden form field named $key.
     *
     * @param string $key The session key where the token will be stored.
     * (Will also be the name of the hidden field name)
     * @return string The generated, base64 encoded token.
     */
    public function generate(string $key): string
    {
        $extra = '';
        if ($this->doOriginCheck === true) {
            $extra = hash('SHA256', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
        }

        // token generation (basically base64_encode any random complex string, time() is used for token expiration)
        $token = base64_encode(time() . $extra . $this->randomString(32));
        // store the one-time token in session
        $_SESSION['csrf_' . $key] = $token;

        return $token;
    }

    /**
     * Generates a random string of given $length.
     *
     * @param int $length The string length.
     * @return string The randomly generated string.
     */
    protected function randomString(int $length): string
    {
        $seed = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijqlmnopqrtsuvwxyz0123456789';
        $max = strlen($seed) - 1;

        $string = '';
        for ($i = 0; $i < $length; ++$i) {
            $string .= $seed[intval(mt_rand(0, $max))];
        }
        return $string;
    }

    /**
     * @param mixed $key
     * @param bool $throwException
     * @return void
     * @throws Exception
     */
    protected function isCsfrMissing($key, bool $throwException): void
    {
        if (!isset($_SESSION['csrf_' . $key])) {
            $this->noError = $this->returnOrException($throwException, 'Missing CSRF session token.');
        }
    }

    /**
     * @param array $origin
     * @param mixed $key
     * @param bool $throwException
     * @return void
     * @throws Exception
     */
    protected function isFormTokenSet(array $origin, $key, bool $throwException): void
    {
        if (!isset($origin[$key])) {
            $this->noError = $this->returnOrException($throwException, 'Missing CSRF form token.');
        }
    }

    /**
     * @param string $hash
     * @param bool $throwException
     * @return void
     * @throws Exception
     */
    protected function isHashOkay(string $hash, bool $throwException): void
    {
        // Origin checks
        if (
            $this->doOriginCheck &&
            hash(
                'SHA256',
                $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']
            ) != substr(base64_decode($hash), 10, 40)
        ) {
            $this->noError = $this->returnOrException($throwException, 'Form origin does not match token origin.');
        }
    }

    /**
     * @param array $origin
     * @param mixed $key
     * @param string $hash
     * @param bool $throwException
     * @return void
     * @throws Exception
     */
    protected function doesTokenMatch(array $origin, $key, string $hash, bool $throwException): void
    {
        // Check if session token matches form token
        if ($origin[$key] != $hash) {
            $this->noError = $this->returnOrException($throwException, 'Invalid CSRF token.');
        }
    }

    /**
     * @param integer|null $time_span
     * @param string $hash
     * @param bool $throwException
     * @return void
     * @throws Exception
     */
    protected function isTokenExpired(?int $time_span, string $hash, bool $throwException): void
    {
        // Check for token expiration
        if (
            $time_span !== null &&
            intval(substr(base64_decode($hash), 0, 10)) + $time_span < time()
        ) {
            $this->noError = $this->returnOrException($throwException, 'CSRF token has expired.');
        }
    }

    /**
     * @param bool $throwException
     * @param string $exceptionString
     * @return bool
     * @throws Exception
     */
    private function returnOrException(bool $throwException, string $exceptionString): bool
    {
        if ($throwException) {
            throw new Exception($exceptionString);
        }
        return false;
    }
}
