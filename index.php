<?php

require __DIR__ . '/vendor/autoload.php';


use Jumbojett\OpenIDConnectClient;

$oidc = new OpenIDConnectClient('https://id.provider.com',
                                'ClientIDHere',
                                'ClientSecretHere');
$oidc->setResponseTypes(array('id_token'));
$oidc->addScope(array('openid'));
$oidc->setAllowImplicitFlow(true);
$oidc->addAuthParam(array('response_mode' => 'form_post'));
$oidc->setCertPath('/path/to/my.cert');
$oidc->authenticate();
$sub = $oidc->getVerifiedClaims('sub');
