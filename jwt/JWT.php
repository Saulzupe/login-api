<?php

namespace Firebase\JWT;
use \DomainException;
use \InvalidArgumentException;
use \UnexpectedValueException;
use \DateTime;

class JWT
{

    /**
     * Cuando estamos checando nbf, iat o el tiempo de expiración,
     * queremos proveer tiempo extra a la cuenta.
     */
    public static $leeway = 0;

    /**
     * Permitimos un tiempo concurrido y lo especificamos
     * lo utilizamos para arregla un valor dentro del unit testing
     */
    public static $timestamp = null;

    public static $supported_algs = array(
        'ES256' => array('openssl', 'SHA256'),
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'RS256' => array('openssl', 'SHA256'),
        'RS384' => array('openssl', 'SHA384'),
        'RS512' => array('openssl', 'SHA512'),
    );

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string        $jwt            EL JWT
     * @param string|array  $key            La key, o mapa de keys.
     *                                      Si el algoritmo usado es asimetrico entonces es una key publica
     * @param array         $allowed_algs   Lista de algoritmos soportados
     *                                      Los algoritmos soportados son 'ES256', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', and 'RS512'
     *
     * @return object El payload JWT es un objeto de PHP
     *
     * @throws UnexpectedValueException     Prevee si jwt fuera invalido
     * @throws SignatureInvalidException    Prevee JWT fuera invalido porque la firma fallo
     * @throws BeforeValidException         Prevee JWT si esta tratando de ser usado antes. Es elegible por  'nbf'
     * @throws BeforeValidException         prevee JWT esta tratando de ser usado antes y es creado por  'iat'
     * @throws ExpiredException            prevee JWT ha sido expirado , es definido por  'exp' claim
     *
     * @uses jsonDecode
     * @uses urlsafeB64Decode
     */
    public static function decode($jwt, $key, array $allowed_algs = array())
    {
        $timestamp = is_null(static::$timestamp) ? time() : static::$timestamp;

        if (empty($key)) {
            throw new InvalidArgumentException('La clave no puede estar vacia');
        }
        $tks = explode('.', $jwt);
        if (count($tks) != 3) {
            throw new UnexpectedValueException('numero erroneo de segmentos');
        }
        list($headb64, $bodyb64, $cryptob64) = $tks;
        if (null === ($header = static::jsonDecode(static::urlsafeB64Decode($headb64)))) {
            throw new UnexpectedValueException('Header encoding invalido');
        }
        if (null === $payload = static::jsonDecode(static::urlsafeB64Decode($bodyb64))) {
            throw new UnexpectedValueException('Claims encoding invalido');
        }
        if (false === ($sig = static::urlsafeB64Decode($cryptob64))) {
            throw new UnexpectedValueException(' Firma encoding Invalida');
        }
        if (empty($header->alg)) {
            throw new UnexpectedValueException('Algoritmo Vacio');
        }
        if (empty(static::$supported_algs[$header->alg])) {
            throw new UnexpectedValueException('Algoritmo no soportado');
        }
        if (!in_array($header->alg, $allowed_algs)) {
            throw new UnexpectedValueException('Algoritmo no permitido');
        }
        if (is_array($key) || $key instanceof \ArrayAccess) {
            if (isset($header->kid)) {
                if (!isset($key[$header->kid])) {
                    throw new UnexpectedValueException('"kid" invalido, incapaz de buscar la llave correcta');
                }
                $key = $key[$header->kid];
            } else {
                throw new UnexpectedValueException('"kid" vaciá, incapaz de buscar la llave correcta');
            }
        }

        // Verificando la firma
        if (!static::verify("$headb64.$bodyb64", $sig, $key, $header->alg)) {
            throw new SignatureInvalidException('La firma de verificación falló');
        }

        // Checanco si nbf esta definido. Este es el tiempo en que el token sera usado.
        // Si el tiempo no esta todavía entonces abortamos.
        if (isset($payload->nbf) && $payload->nbf > ($timestamp + static::$leeway)) {
            throw new BeforeValidException(
                'No se puede manejar el token antes de ' . date(DateTime::ISO8601, $payload->nbf)
            );
        }

        // Revisamos si el token no ha sido creado anteriormente . Esto prevee que los tokens creados
        // no hayan sido usados por usuarios pasados
        if (isset($payload->iat) && $payload->iat > ($timestamp + static::$leeway)) {
            throw new BeforeValidException(
                'No se puede manejar el token antes de ' . date(DateTime::ISO8601, $payload->iat)
            );
        }

        // Revisamos si el token ha sido expirado.
        if (isset($payload->exp) && ($timestamp - static::$leeway) >= $payload->exp) {
            throw new ExpiredException('El token ha caducado');
        }

        return $payload;
    }

    /**
     * Convertimos de PHP objetos o Arrays a JWT strings
     *
     * @param object|array  $payload    PHP object o array
     * @param string        $key        La llave  key.
     *
     * @param string        $alg        la firma del algoritmo.
     * @param mixed         $keyId
     * @param array         $head       Un array con un header de elementos para unir
     *
     * @return string A signed JWT
     *
     * @uses jsonEncode
     * @uses urlsafeB64Encode
     */
    public static function encode($payload, $key, $alg = 'HS256', $keyId = null, $head = null)
    {
        $header = array('typ' => 'JWT', 'alg' => $alg);
        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }
        if ( isset($head) && is_array($head) ) {
            $header = array_merge($head, $header);
        }
        $segments = array();
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($header));
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($payload));
        $signing_input = implode('.', $segments);

        $signature = static::sign($signing_input, $key, $alg);
        $segments[] = static::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    /**
     * firmando un string y dando la firma al algoritmo
     *
     * @param string            $msg    mensaje para la firma
     * @param string|resource   $key    la llave secreta
     * @param string            $alg    la firma del algoritmo
     *
     * @return string un mensaje encriptado
     *
     * @throws DomainException algoritmos no especificados no soportados
     */
    public static function sign($msg, $key, $alg = 'HS256')
    {
        if (empty(static::$supported_algs[$alg])) {
            throw new DomainException('Algoritmo no soportado');
        }
        list($function, $algorithm) = static::$supported_algs[$alg];
        switch($function) {
            case 'hash_hmac':
                return hash_hmac($algorithm, $msg, $key, true);
            case 'openssl':
                $signature = '';
                $success = openssl_sign($msg, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL incapaz de firmar datos");
                } else {
                    return $signature;
                }
        }
    }

    /**
     * verificando el mensaje con la firma, llave y metodo. No todos los metodos son asimetricos
     * , Debemos separlo y verificarlo
     *
     * @param string            $msg        El mensaje original
     * @param string            $signature  firma origina
     * @param string|resource   $key        Para HS*, un string  trabaja en key . for RS*, debe ser un recurso para  openssl public key
     * @param string            $alg        The algorithm
     *
     * @return bool
     *
     * @throws DomainException Invalid Algorithm or OpenSSL failure
     */
    private static function verify($msg, $signature, $key, $alg)
    {
        if (empty(static::$supported_algs[$alg])) {
            throw new DomainException('Algoritmo no soportado');
        }

        list($function, $algorithm) = static::$supported_algs[$alg];
        switch($function) {
            case 'openssl':
                $success = openssl_verify($msg, $signature, $key, $algorithm);
                if ($success === 1) {
                    return true;
                } elseif ($success === 0) {
                    return false;
                }
                // returns 1 en exito, 0 en falla, -1 un error.
                throw new DomainException(
                    'OpenSSL error: ' . openssl_error_string()
                );
            case 'hash_hmac':
            default:
                $hash = hash_hmac($algorithm, $msg, $key, true);
                if (function_exists('hash_equals')) {
                    return hash_equals($signature, $hash);
                }
                $len = min(static::safeStrlen($signature), static::safeStrlen($hash));

                $status = 0;
                for ($i = 0; $i < $len; $i++) {
                    $status |= (ord($signature[$i]) ^ ord($hash[$i]));
                }
                $status |= (static::safeStrlen($signature) ^ static::safeStrlen($hash));

                return ($status === 0);
        }
    }

    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input JSON string
     *
     * @return object Object representation of JSON string
     *
     * @throws DomainException Provided string was invalid JSON
     */
    public static function jsonDecode($input)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {

            $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        } else {

            $max_int_length = strlen((string) PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
            $obj = json_decode($json_without_bigints);
        }

        if (function_exists('json_last_error') && $errno = json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * Encode a PHP object into a JSON string.
     *
     * @param object|array $input A PHP object or array
     *
     * @return string JSON representation of the PHP object or array
     *
     * @throws DomainException Provided object could not be encoded to valid JSON
     */
    public static function jsonEncode($input)
    {
        $json = json_encode($input);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new DomainException('Null result with non-null input');
        }
        return $json;
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     *
     * @return string The base64 encode of what you passed in
     */
    public static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     *
     * @return void
     */
    private static function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters' //PHP >= 5.3.3
        );
        throw new DomainException(
            isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno
        );
    }

    /**
     * Get the number of bytes in cryptographic strings.
     *
     * @param string
     *
     * @return int
     */
    private static function safeStrlen($str)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str, '8bit');
        }
        return strlen($str);
    }
}
