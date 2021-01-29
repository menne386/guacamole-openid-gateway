<?php

if(!defined('_GATEWAY')) {
	die("nope");
}

$config=array(
	'app-domain' => 'thedomainthissiterunsons.nl',
	'domain' => 'tennantdomain.com',
	'app-id' => 'azure app registration id',
	'claim'  => 'preferred_username',
	'key'    => 'Amazing secret key in hex',
	'expire' => 60*60*12 
);

$connection = array(
	"username"=> '#USER#',
	"expires" => (time()+($config['expire'])) * 1000,
	"connections"=>array(
		"Connection Name" => array(
			"protocol"=>"rdp",
			"id" => '#USER#_'.time(),
			"parameters" => array(
				"hostname" => "The host we are connecting to",
				"client-name"=> "GUAC_#USER#",
				"domain"=> "The domain we are connecting to",
				"enable-font-smoothing"=> true,
				"ignore-cert"=> true,
				"password"=> "#PASSWORD#",
				"security"=> "rdp",
				"username"=> "#USER#"
			)

		)
	)
);

