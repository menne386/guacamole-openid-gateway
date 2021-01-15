<?php 
#Author Menne Kamminga

define('_GATEWAY',true);

#need config array
require_once("config.php");

#start a session: the date in sessionname will invalidate & restart sessions 00:00 every day.
session_name(md5(date('dmY').md5($config['app-id'])));
session_start();

#Load classes for openID
require __DIR__ . '/vendor/autoload.php';
use Jumbojett\OpenIDConnectClient;

#this function displays a basic HTML header with some minimal styling
function htmlheader() {
?><!DOCTYPE html>
<html>
<head>
	<title>RDP-App-Redirector</title>
	<meta http-equiv="refresh" content="180"/>
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
	<script src="//code.iconify.design/1/1.0.6/iconify.min.js"></script>
</head>
<body>
<?php
}

#This function will display html footer...
function htmlfooter() {
?></body>
</html>
<?php
}


#Check if we have a username in the session: if not: login with openID:
if(!isset($_SESSION['username']) || $_SESSION['username']=="") {
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
	if($_SESSION['username']=="") {
		die("The auth provider did not send a preferred_username token");
	}
}

#Check if a password was posted and username is set:
if(isset($_POST['pwd']) && isset($_SESSION['username'])) {
	#array with information that can be inserted into the configuration:
	$replacements = array('#USER#'=>$_SESSION['username'],'#PASSWORD#'=>$_POST['pwd']);
	
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
	sodium_memzero($binkey);
	sodium_memzero($token);
	sodium_memzero($hash);
	sodium_memzero($replacements['#PASSWORD#']);
	sodium_memzero($_POST['pwd']);
	sodium_memzero($config['key']);
	array_walk_recursive($tokenArray,function(&$item,$key){
		if(is_string($item)) {
			sodium_memzero($item);
		}
	});
	if(isset($_SESSION['token'])) {		
		#We have a token in the session: redirect to main page:
		header("Location: /#/");
		die('Redirect');
	}
	die('Failed to generate valid token');
}

#From this point on in the script, we will never need the secret key again, forget it:
sodium_memzero($config['key']);

#If we post or get with "removetoken" parameter: all session stuff is destroyed.
if(isset($_REQUEST['removetoken'])) {
	sodium_memzero($_SESSION['token']);
	sodium_memzero($_SESSION['guacsession']);
	unset($_SESSION['token']);
	unset($_SESSION['guacsession']);
	unset($_SESSION['username']);
	header('Location: /');
	die('Redirect...');
}

#Check if we have received an "open" command:
$app = isset($_REQUEST['open']) ? $_REQUEST['open']: false;
if($app && isset($_SESSION['token']) && isset($connection['connections'][$app]) ) {
	#@todo: hardcoded api URL
	$apiUrl = "http://localhost:8080/guacamole/api/tokens";
	
	#encode the app name for guacamole
	$appDirector=base64_encode("$app\0c\0json");
	
	
	if(isset($_SESSION['guacsession'])) {
		#Check if guacamole session key is still valid:
		$ch = curl_init( $apiUrl );
		$payload = 'token='.urlencode($_SESSION['guacsession']);
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $payload );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
		$result = curl_exec($ch);
		curl_close($ch);
		$res = json_decode($result,true);
		if(!isset($res['authToken']) || $res['authToken'] != $_SESSION['guacsession']) {
			unset($_SESSION['guacsession']);
		}
	}
	
	
	if(!isset($_SESSION['guacsession'])) {
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
			echo "<h1>Token is niet (meer) geldig, meld u opnieuw aan.</h1>";
			echo "<pre>error: $result</pre>";
		} else {
			$_SESSION['guacsession'] = $res['authToken'];
			#fresh guacsession open the app with the token in the URL:
			header("Location: /guacamole/#/client/".$appDirector."?token=".urlencode($_SESSION['guacsession']));
			die("Redirect...");
		}
	}
	
 	if(isset($_SESSION['guacsession'])) {
		#We have a guacsession: open the app without the token in the URL:
		header("Location: /guacamole/#/client/".$appDirector);
		die("Redirect...");
	} else {
		#We dont have a valid guacsession:
		echo "<h1>Sessie is niet geldig, meld u opnieuw aan.</h1>";
	}
}



#Output the header:
htmlheader();


if(!isset($_SESSION['token'])) {
	#We dont have a valid token yet: present a lock screen with a password box:
?> 
	<br/><br/>
	<form class="loginform" method="post" action="/" title="Uw wachtwoord is nodig voor het openen van beveiligde applicaties">
		<div class="shield">
		<span class="iconify largeicon" data-icon="mdi-shield-lock-outline">Wachtwoord:</span>
		</div>
		<input class="passwordbox" type="password"  name="pwd"/>
	</form>
<?php
} else {
	#We do have a valid token: present list of apps in token configuration:
	echo '<a class="rr" href="/?removetoken"><span class="iconify" data-icon="mdi-shield-lock" title="Afmelden voor apps">lock</span></a>';
	foreach($connection['connections'] as $name=>$conf) {
		echo '<a class="ll" href="/?open='.$name.'" target="__'.$name.'" title="'.$name.'"><div class="app"><div><span class="iconify" data-icon="'.$conf['parameters']['icon'].'">'.$name.'</span></div>'.$name.'</div></a>';
	}
}

#output footer:
htmlfooter();

