<?php 
define('_GATEWAY',true);
require_once("config.php");

session_start();

require __DIR__ . '/vendor/autoload.php';
use Jumbojett\OpenIDConnectClient;

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
	if($_SESSION['username']=="") {
		die("The auth provider did not send a preferred_username token");
	}
}




if(isset($_POST['pwd'])) {
	//Password was posted: create the token and put it in _SESSION
	$replacements = array('#USER#'=>$_SESSION['username'],'#PASSWORD#'=>$_POST['pwd']);
	$tokenArray = $connection;
	array_walk_recursive($tokenArray,function(&$item,$key){
		global $replacements;
		if(is_string($item)) {
			$item=str_replace(array_keys($replacements),array_values($replacements),$item);
		}
	});

	$binkey = sodium_hex2bin($config['key']);
	$token = json_encode($tokenArray,JSON_PRETTY_PRINT);

	$hash = hash_hmac('sha256',$token,$binkey,true);
	//echo "Hash:$hash\n";
	$cipher = "aes-128-cbc";
	if (in_array($cipher, openssl_get_cipher_methods())) {
		$iv = sodium_hex2bin("00000000000000000000000000000000");
		$cyphertext = openssl_encrypt($hash.$token, $cipher, $binkey, $options=OPENSSL_RAW_DATA, $iv);
		$_SESSION['token'] = sodium_bin2base64($cyphertext,SODIUM_BASE64_VARIANT_ORIGINAL);
	}

	//Clean all the funky stuff from memory.
	sodium_memzero($config['key']);
	sodium_memzero($token);
	sodium_memzero($hash);
	sodium_memzero($replacements['#PASSWORD#']);
	sodium_memzero($_POST['pwd']);
	array_walk_recursive($tokenArray,function(&$item,$key){
		if(is_string($item)) {
			sodium_memzero($item);
		}
	});
}

if(isset($_POST['logon']) && isset($_SESSION['token'])) {
	//header("Location: /guacamole/#/?data=".urlencode($_SESSION['token']));

	
	echo "<h1>Redirect failed</h1>";

echo '<form name="_autologon" method="get" action="/guacamole/" target="_rdp_connection">';
echo '<input type="hidden" name="data" value="'.$_SESSION['token'].'" >';
echo '</form>';
?>
<script type="text/javascript">
window.onload=function(){
	document.forms["_autologon"].submit();
};
</script>
<?php
}

if(isset($_POST['removetoken'])) {
	sodium_memzero($_SESSION['token']);
	unset($_SESSION['token']);
}

echo "<pre>Welkom:";
print_r($_SESSION['username']);

if(!isset($_SESSION['token'])) {

?> 
	<form method="post" action="/">
		Wachtwoord nodig voor beveiligde verbinding<input type="password" name="pwd"/>
	</form>

<?php
} else {
?>
<form method="post" action="/" target="_rdp_connection">
<input type="submit" name="logon" value="Aanmelden" >
</form>
<form method="post" action="/" >
<input type="submit" name="removetoken" value="nieuw token" >
</form>
<?php
}


