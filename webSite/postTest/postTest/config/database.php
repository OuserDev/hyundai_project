<?php
$servername = "localhost";
$username = "webuser";
$password = "Qkrqntjd0@";
$dbname = "website_db";

try{
	$pdo = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
	$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e){
	die("connection failed: " . $e->getmessage());
}
?>
