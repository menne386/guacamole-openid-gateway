<?php

if(!defined('_GATEWAY')) {
	die("nope");
}

$config=array(
	'domain' => 'Azure.ad.tennant.domain.com',
	'app-id' => 'application id in azure app registry',
	'claim'  => 'preferred_username',
	'key'    => 'super secret encryption key'
);

