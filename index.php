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
	//@todo: create the token and put it in _SESSION
}
echo "<pre>Welkom:";
print_r($_SESSION['username']);



if(!isset($_SESSION['token'])) {
?> 
	<form method="post" action="/">
		Wachtwoord nodig voor beveiligde verbinding<input type="password" name="pwd"/>
		<input type="submit"/>
	</form>

<?php
} else {
	print_r($_SESSION['token']);
}

if(isset($_GET['pastetoken']) ){
?>
<form method="post" action="/guacamole/#/" >
<textarea name="data" rows="10" cols="30" placeholder="-- paste token here --">
</textarea>
<input type="submit"/>
</form>
<?php
}
