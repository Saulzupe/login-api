<?php
require __DIR__.'/../jwt/JWT.php';
require __DIR__.'/../jwt/ExpiredException.php';
require __DIR__.'/../jwt/SignatureInvalidException.php';
require __DIR__.'/../jwt/BeforeValidException.php';

use \Firebase\JWT\JWT;

class JwtHandler
{
    protected $jwtSecreto;
    protected $token;
    protected $issuedAt;
    protected $expira;
    protected $jwt;

    public function __construct()
    {
        // Tiempo de zona horaria
        date_default_timezone_set('America/Mexico_City');
        $this->issuedAt = time();
        // Tiempo del token ( 1hra )
        $this->expira = $this->issuedAt + 3600;
        // Ingresamos la firma secreta
        $this->jwtSecreto = "this_is_my_secret";
    }
    // Codificando el token
    public function _jwt_encode_data($iss, $data) {
        $this->token = array(
          // Agrengando el identificador del token
            "iss"=>$iss,
            "aud"=>$iss,
            // Agregando un tiempo concurrido al token, para identificar cuando fue usado
            "iat" => $this->issuedAt,
            // Tiempo de expiración
            "exp" => $this->expira,
            // Payload
            "data"=>$data
        );

        $this->jwt = JWT::encode($this->token, $this->jwtSecreto);
        return $this->jwt;
    }

    protected function _errMsg($msg){
        return [
            "auth"=>0,
            "mensaje" => $msg
        ];
    }
    // Decodificando el token
    public function _jwt_decode_data($jwt_token){
        try {
            $decode = JWT::decode($jwt_token, $this->jwtSecreto, array('HS256'));
            return [
                "auth"=>1,
                "data" => $decode->data
            ];
        } catch (\Firebase\JWT\ExpiredException $e)
        {
            return $this->_errMsg($e->getMessage());
        }  catch (\Firebase\JWT\SignatureInvalidException $e)
        {
            return $this->_errMsg($e->getMessage());
        } catch (\Firebase\JWT\BeforeValidException $e)
        {
            return $this->_errMsg($e->getMessage());
        } catch (\DomainException $e)
        {
            return $this->_errMsg($e->getMessage());
        } catch (\InvalidArgumentException $e)
        {
            return $this->_errMsg($e->getMessage());
        } catch (\UnexpectedValueException $e)
        {
            return $this->_errMsg($e->getMessage());
        }
    }
}