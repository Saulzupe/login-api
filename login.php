<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Content-Type: application/json; charset=UTF-8 *");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

function msg($success, $estado, $message, $extra = []){
    return array_merge([
        'success' => $success,
        'estado' => $estado,
        'mensaje' => $message
    ], $extra);
}

require __DIR__.'/classes/Database.php';
require __DIR__.'/classes/JwtHandler.php';

$dbConexcion = new Database();
$conn = $dbConexcion->dbConexion();

$data = json_decode(file_get_contents("php://input"));
$returnData = [];

// Si la peticion es distinto a POST
if($_SERVER["REQUEST_METHOD"] != "POST"):
    $returnData = msg(0,404, 'Página no encontrada');
// Verificando que no existan archivos vacios
elseif(!isset($data->email)
        || !isset($data->password)
        || empty(trim($data->email))
        || empty(trim($data->password))):

    $fields = ['fields' => ['email','password']];
    $returnData = msg(0,422, 'Todos los campos son requeridos', $fields);

    // SI no hay campos vacios entonces
else:
    $email = trim($data->email);
    $password = trim($data->password);

    // Verificando el formato del email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)):
        $returnData = msg(0,422, 'Email Invalido');

    elseif (strlen($password) < 8 ): // Verificando que la longitud de la contraseña sea de 8
        $returnData = msg(0,422, 'Tu contraseña debe contener 8 caracteres');
    // El usuario esta autorizado apra la accion de login
    else:
        try{
            $fetchUserPorEmail = "SELECT * FROM `usuarios` WHERE `email`=:email";
            $query_stmt = $conn->prepare($fetchUserPorEmail);
            $query_stmt->bindValue(':email', $email, PDO::PARAM_STR);
            $query_stmt->execute();

            // Si encontramos el usuario por su email
            if ($query_stmt->rowCount()):
                $row = $query_stmt->fetch(PDO::FETCH_ASSOC);
                $checkPassword = password_verify($password, $row['password']);
                // Verificamos si el password es correcto o no
                // Si es correcto entonces pasamos el token
                if($checkPassword):
                    $jwt = new JwtHandler();
                    $token = $jwt->_jwt_encode_data(
                      'http://localhost/login-api/',
                      array("usuarioId" => $row['id'])
                    );

                    $returnData = [
                        'success' => 1,
                        'mensaje' => 'Has iniciado con éxito',
                        'token' => $token
                    ];
                    // Si el password es invalido
                else:
                    $returnData = msg(0,422, 'Password invalido');
                endif;
                // SI el usuadio no es encontrado por el email entonces mandamos un mensaje de error
            else:
                $returnData = msg(0,422, 'Email No valido');
            endif;
        } catch (PDOException $e) {
            $returnData = msg(0, 500, $e->getMessage());
        }
    endif;
endif;

echo  json_encode($returnData);