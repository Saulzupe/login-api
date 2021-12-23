<?php

class Database
{
    private $dbHost = 'localhost';
    private  $dbName = 'login-sys';
    private  $dbUsuario = 'root';
    private $dbPassword = '';

    public function dbConexion(){
        try{
            $conn = new PDO('mysql:host='.$this->dbHost.';dbname='.$this->dbName,$this->dbUsuario,$this->dbPassword);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            return $conn;
        } catch (PDOException $e){
            echo "Error en la conexicón".$e->getMessage();
            exit;
        }
    }
}