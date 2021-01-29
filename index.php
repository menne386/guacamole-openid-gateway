<?php 
#Author Menne Kamminga

define('_GATEWAY',true);

#need config array
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

session_name(hash("sha1",date('dmY').":".$config['app-id'].":".$_SERVER['REMOTE_ADDR']));

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

#this function displays a basic HTML header with some minimal styling
function htmlheader($refresh = 180) {
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
	<script src="/iconify.min.js"></script>
	<script>
	function checkSession() {
		var xhttp = new XMLHttpRequest();
		xhttp.responseType = 'text';
		xhttp.overrideMimeType("application/json");
		xhttp.onreadystatechange = function() {
			if (this.readyState == 4 && this.status == 200) {
				var jsonResponce = JSON.parse(this.responseText);
				//console.log();
				if(jsonResponce['result']!='ok') {
					window.location = '/?removetoken';
				}
			}
		};
		xhttp.open("GET", "/?checkSession", true);
		xhttp.send();
	}
	setInterval(checkSession, 10000);
	setTimeout(checkSession, 1000);
	
	</script>
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

function cleanmem(&$item) {
	if(isset($item) && is_string($item)) {
		sodium_memzero($item);
	}
}

#session checkup.
if(isset($_REQUEST['checkSession'])) {
	if(isset($_SESSION['ctr'])) {
		$_SESSION['ctr']++;
		die('{"result":"ok","ctr":'.$_SESSION['ctr'].'}');
	}
	
	die('{"result":"error"}');
}
if(!isset($_SESSION['ctr'])) {
	$_SESSION['ctr'] = (int)1;
}


#Check if we have a username in the session: if not: login with openID:
if(!isset($_SESSION['username']) || $_SESSION['username']=="") {
	if(isset($_POST['login']) || isset($_POST['id_token'])|| isset($_POST['state'])|| isset($_POST['session_state'])) {
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
			if($_SESSION['username']=="") {
				die("The auth provider did not send a preferred_username token");
			}
			htmlheader();
			echo '<script>window.opener.location.reload(false);window.close();</script>This page can be closed, you are authenticated as '.$_SESSION['displayname'];
			htmlfooter();
			die();
		} catch(Exception $e) {
			die("Failed to authenticate from ".$_SERVER['HTTP_REFERER']);
		}
	} else {
		htmlheader(180);
	?> 
		<br/><br/>
		<form name="autologon" class="loginform" method="post" action="/" title="Logon" target="_blank">
			<a href="javascript: document.autologon.submit();">
				<div class="shield">
					<span class="iconify largeicon" data-icon="mdi-shield-lock-outline">Password:</span>
				</div>
				<input type="hidden" name="login" value="true" />
				Click here if authentication popup did not open.
				<script>document.autologon.submit();</script>
			</a>
		</form>
	<?php	
		htmlfooter();
		die();
	}
} else {
	unset($_SESSION['do_login']);
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
	cleanmem($binkey);
	cleanmem($token);
	cleanmem($hash);
	cleanmem($replacements['#PASSWORD#']);
	cleanmem($_POST['pwd']);
	cleanmem($config['key']);
	array_walk_recursive($tokenArray,function(&$item,$key){
		cleanmem($item);
	});
	if(isset($_SESSION['token'])) {		
		#We have a token in the session: redirect to main page:
		header("Location: /#/");
		die('Redirect');
	}
	die('Failed to generate valid token');
}

#From this point on in the script, we will never need the secret key again, forget it:
cleanmem($config['key']);

#If we post or get with "removetoken" parameter: all session stuff is destroyed.
if(isset($_REQUEST['removetoken'])) {
	cleanmem($_SESSION['token']);
	cleanmem($_SESSION['guacsession']);
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
	$apiUrl = "http://127.0.0.1:8080/guacamole/api/tokens";
	
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
			#fresh guacsession open the app with the token in the URL: @TODO: dont put it in the URL: put it in localStorage.setItem("GUAC_AUTH", "Smith");
			htmlheader();
			echo "<script>";
			echo 'window.localStorage.setItem("GUAC_AUTH", \''.$result.'\');';
			echo 'window.location.href = "/guacamole/#/client/'.$appDirector.'";';
			echo "</script>";
			htmlfooter();
			die();
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
	<form class="loginform" method="post" action="/" title="Your password is required for secure apps">
		<h3><?php echo $_SESSION['displayname'];?></h3>
		<div class="shield">
		<span class="iconify largeicon" data-icon="mdi-shield-lock-outline">Password:</span>
		</div>
		<input class="passwordbox" type="password"  name="pwd"/>
	</form>
<?php
} else {
	#We do have a valid token: present list of apps in token configuration:
	echo '<a class="rr" href="/?removetoken"><span class="iconify" data-icon="mdi-shield-lock" title="Logoff for apps">lock</span></a>';
	foreach($connection['connections'] as $name=>$conf) {
		echo '<a class="ll" href="/?open='.$name.'" target="__'.$name.'" title="'.$name.'"><div class="app"><div><span class="iconify" data-icon="'.$conf['parameters']['icon'].'">'.$name.'</span></div>'.$name.'</div></a>';
	}
}

#output footer:
htmlfooter();

