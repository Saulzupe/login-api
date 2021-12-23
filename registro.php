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
// Incluyendo la base de datos y creando el objeto
require __DIR__.'/classes/Database.php';
$dbConexion = new Database();
$conn = $dbConexion->dbConexion();

// Trayendo la información con GET
$data = json_decode(file_get_contents("php://input"));
$returnData = [];

// Verificando el metodo de petición
if($_SERVER["REQUEST_METHOD"] != "POST") :

    $returnData = msg(0,404, 'Página no encontrada');
    // Verificando que no exista campos vacios
elseif(!isset($data->nombre)
    || !isset($data->email)
    || !isset($data->password)
    || empty(trim($data->nombre))
    || empty(trim($data->email))
    || empty(trim($data->password))):

    $fields = ['fields' => ['nombre','email', 'password']];
    $returnData = msg(0,422, 'Todos los campos son requeridos', $fields);
else:
    // Si no existe campos vacios entonces
    $nombre = trim($data->nombre);
    $email = trim($data->email);
    $password = trim($data->password);

    if(!filter_var($email, FILTER_VALIDATE_EMAIL)):
        $returnData = msg(0,422, 'Email Invalido');
    elseif (strlen($password) < 8):
        $returnData = msg(0,422, 'Tu contraseña debe contener almenos 8 caracteres');
    elseif (strlen($nombre) < 3):
        $returnData = msg(0,422, 'Tu nombre debe contener mas de 3 caracteres');
    else:
        try {
            $checkEmail = "SELECT `email` FROM `usuarios` WHERE `email`=:email";
            $checkEmail_stmt = $conn->prepare($checkEmail);
            $checkEmail_stmt->bindValue(':email', $email, PDO::PARAM_STR);
            $checkEmail_stmt->execute();

            // Revisamos si el correo ya existe
            if ($checkEmail_stmt->rowCount()):
                $returnData = msg(0,422, 'Este email ya esta en uso');
            else:
                $Query = "INSERT INTO `usuarios`(`nombre`,`email`,`password`) VALUES(:nombre,:email,:password)";

                $Query_stmt = $conn->prepare($Query);

                // Vinculando
                $Query_stmt->bindValue(':nombre', htmlspecialchars(strip_tags($nombre)), PDO::PARAM_STR);
                $Query_stmt->bindValue(':email',$email, PDO::PARAM_STR);
                $Query_stmt->bindValue(':password', password_hash($password, PASSWORD_DEFAULT), PDO::PARAM_STR);

                $Query_stmt->execute();
                $returnData = msg(1,201, 'Registro con exito');
            endif;
        } catch (PDOException $e) {
            $returnData = msg(0,500, $e ->getMessage());
        }
    endif;
endif;
echo json_encode($returnData);