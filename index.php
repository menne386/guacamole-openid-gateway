<?php

define("_GATEWAY",true);

require_once("config.php");

#start a session: the date in sessionname will invalidate & restart sessions 00:00 every day.
#  The REMOTE_ADDR bit will ensure that hackers from other systems will not break into the session
#  It is advised that session are stored in a redis server/cluster WITHOUT PERSISTENCE

$secure = true; # if you only want to receive the cookie over HTTPS
$httponly = true; # prevent JavaScript access to session cookie
$samesite = 'none';
$hostname = $config['app-domain'];

header("Access-Control-Allow-Origin: https://login.microsoftonline.com:443");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: GET, POST");
header("Access-Control-Allow-Headers: Content-Type, Cookie , *");

session_name(hash("sha1",date('dmY').":".$config['js-app-id'].":".$_SERVER['REMOTE_ADDR']));

if(PHP_VERSION_ID < 70300) {
	session_set_cookie_params(0, '/; samesite='.$samesite, $hostname, $secure, $httponly);
} else {
	session_set_cookie_params([
		'lifetime' => 0,
		'path' => '/',
		'domain' => $hostname,
		'secure' => $secure,
		'httponly' => $httponly,
		'samesite' => $samesite
	]);
}
session_start();

#Load classes for openID
require __DIR__ . '/vendor/autoload.php';
use Jumbojett\OpenIDConnectClient;

#Check if we have a username in the session: if not: login with openID:

if(isset($_POST['login']) || isset($_POST['id_token'])|| isset($_POST['state'])|| isset($_POST['session_state'])) {
	if(isset($_POST['login'])) {
		$_SESSION['loginType']=$_POST['login'];
	}
	#Do microsoft openID auth
	try{
		$oidc = new OpenIDConnectClient('https://login.microsoftonline.com/'.$config['domain'].'/v2.0',
			$config['app-id'],
			null);
		$oidc->setResponseTypes(array('id_token'));
		$oidc->addScope(array('openid','email','profile'));
		$oidc->setAllowImplicitFlow(true);
		$oidc->addAuthParam(array('response_mode' => 'form_post'));
		$oidc->authenticate();
		
		$_SESSION['username']=$oidc->getVerifiedClaims($config['claim']);
		$_SESSION['displayname'] = $oidc->getVerifiedClaims($config['displayclaim']);
		if($_SESSION['username']=="" || $_SESSION['displayname'] == "") {
			die("The auth provider did not send a ".$config['claim']." or a ".$config['displayclaim']." claim");
		}
		if(isset($_SESSION['loginType']) && $_SESSION['loginType']=="newTab") {
			echo '<script>window.opener.location.reload(); window.close();</script>';
			die();
			
		}
		header("Location: /");
		die("Redirect...");
	} catch(Exception $e) {
		die("Failed to authenticate from ".$_SERVER['HTTP_REFERER']);
	}
}


function cleanmem(&$item) {
	if(isset($item) && is_string($item)) {
		sodium_memzero($item);
	}
}

function getApps() {
	global $connection;
	
	$appArray = array();
	foreach($connection['connections'] as $name=>$conf) {
		$appArray[] = array(
			"name"=>$name,
			'icon'=>$conf['parameters']['icon'],
			'url'=>'/guacamole/#/client/'.base64_encode("$name\0c\0json")
		);
	}
	return $appArray;
}

if(isset($_REQUEST['createToken'])) {
	header('Content-Type: application/json');
	if(isset($_POST['pwd']) && isset($_SESSION['username'])) {
		#array with information that can be inserted into the configuration:
		$replacements = array('#USER#'=>$_SESSION['username'],'#PASSWORD#'=>$_POST['pwd']);
		
		
		
		#TODO: perhaps check the username/password with an AD bind.
		
		#Clean the password from memory
		cleanmem($_POST['pwd']);

		#Copy the $connection array and replace values in it:
		$tokenArray = $connection;
		array_walk_recursive($tokenArray,function(&$item,$key){
			global $replacements;
			if(is_string($item)) {
				$item=str_replace(array_keys($replacements),array_values($replacements),$item);
			}
		});

		#Encode all connection information with the password into json text:
		$token = json_encode($tokenArray,JSON_PRETTY_PRINT);

		#Sign the plaintext token with hmac:
		$binkey = sodium_hex2bin($config['key']);
		$hash = hash_hmac('sha256',$token,$binkey,true);

		#Encrypt the hash+token with aes-128-cbc and store it in the session:
		$cipher = "aes-128-cbc";
		if (in_array($cipher, openssl_get_cipher_methods())) {
			$iv = sodium_hex2bin("00000000000000000000000000000000");
			$cyphertext = openssl_encrypt($hash.$token, $cipher, $binkey, $options=OPENSSL_RAW_DATA, $iv);
			$_SESSION['token'] = sodium_bin2base64($cyphertext,SODIUM_BASE64_VARIANT_ORIGINAL);
		}

		#Clean all the secret stuff from memory:
		cleanmem($binkey);
		cleanmem($token);
		cleanmem($hash);
		cleanmem($replacements['#PASSWORD#']);
		cleanmem($config['key']);
		array_walk_recursive($tokenArray,function(&$item,$key){
			cleanmem($item);
		});
		array_walk_recursive($data,function(&$item,$key){
			cleanmem($item);
		});
		if(isset($_SESSION['token'])) {
			$response = array('status'=>'ok');
			$response['apps'] = getApps();
			
			echo json_encode($response);
			exit();
		}
		die(json_encode(array('status'=>'error','message'=>'Token generation failed')));
	}
	die(json_encode(array('status'=>'error','message'=>'Missing parameters')));
}


if(isset($_REQUEST['getConfig'])) {
	header('Content-Type: application/json');
	$response = array(
		"haveUser" => isset($_SESSION['username']),
		"displayname" => isset($_SESSION['displayname']) ? $_SESSION['displayname']:"",
		"haveToken" => isset($_SESSION['token']),
	);
	if(isset($_SESSION['token'])) {
		$response['apps'] = getApps();
	}

	echo json_encode($response);
	exit();
}

if(isset($_REQUEST['openSession'])) {
	
	header('Content-Type: application/json');
	$response = array(
		"status" => 'ok',
		"GT"=>false
	);
	
	#@todo: hardcoded api URL
	$apiUrl = "http://127.0.0.1:8080/guacamole/api/tokens";
	
	#Check if client has valid session key:
	if(isset($_POST['authToken'])) {
		$ch = curl_init( $apiUrl );
		$payload = 'token='.urlencode($_POST['authToken']);
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $payload );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
		$result = curl_exec($ch);
		curl_close($ch);
		$res = json_decode($result,true);
		if($_POST['authToken'] == $res['authToken']) {
			#The session is still valid:
			echo json_encode($response);
			exit();
		}
	}
	
	
	#Create guacamole session:
	#Post to the guacamole api to exchange the full encrypted token for a session token: (passes protected local network)
	$ch = curl_init( $apiUrl );
	$payload = 'data='.urlencode($_SESSION['token']);
	curl_setopt( $ch, CURLOPT_POSTFIELDS, $payload );
	curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
	$result = curl_exec($ch);
	curl_close($ch);
	$res = json_decode($result,true);
	if(!isset($res['authToken'])) {
		#No authToken received from API: cannot login
		$response['status'] = 'token_fail';
	} else {
		#We Succesfully created a guacSession:
		$response['GT'] = $result;
	}
	
	echo json_encode($response);
	exit();
}



?><!DOCTYPE html>
<html>
    <head>
		<title>RDP-App-Redirector</title>
		<style>
		html{
			font-family: sans-serif;
			background-color: transparent;
		}
		.iconify{
			width: 2em;
			height: 2em;
		}
		.largeicon{
			width: 4em;
			height: 4em;
			
		}
		.rr{
			float: right;
			color: black;
			text-decoration: none;
		}
		
		.ll {
			float: left;
			color: black;
			text-decoration: none;
		}
		.ll:hover,.rr:hover {
			color: blue;
		}
		
		.loginform{
			text-align:center;
		}
		.passwordbox{
			text-align:center;
			border-radius: 0.4em;
			padding: 0.2em;
			border: 1px solid black;
		}
		.app{
			text-align:center;
			padding: 0.5em;
			width: 8em;
		}
		</style>	
    </head>
    <body>
        <div id="UI">
			<form method="post" id="logonUI" class="loginform" action="/" title="Your password is required for secure apps">
				<h3 id="displayname">&nbsp;</h3>
				<div class="shield">
				<span class="iconify largeicon" data-icon="mdi-shield-lock-outline">Password:</span>
				</div>
				<input id="passwordentry" class="passwordbox" type="password" name="pwd" readonly placeholder="Loading..." />
			</form>
        </div>
        <pre id='out'></pre>
        <script async src='/ajax-client.js'></script>
		<script async src="/iconify.min.js"></script>        
    </body>
</html>
