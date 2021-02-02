// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


///////////////////////////////
// OidcClient config
///////////////////////////////
Oidc.Log.logger = console;
Oidc.Log.level = Oidc.Log.INFO;

var client;

function makeRequest(method, url, post=null) {
    return new Promise(function (resolve, reject) {
        let xhr = new XMLHttpRequest();
		xhr.responseType = 'text';
		xhr.overrideMimeType("application/json");
        xhr.open(method, url,true);
		
        xhr.onload = function () {
            if (this.status >= 200 && this.status < 300) {
                resolve(xhr.responseText);
            } else {
                reject({
                    status: this.status,
                    statusText: xhr.statusText
                });
            }
        };
        xhr.onerror = function () {
            reject({
                status: this.status,
                statusText: xhr.statusText
            });
        };
		if(post) {
			xhr.send(post);
		} else {
			xhr.send();
		}
    });
}


function openurl(url) {
	window.location = url;
}

///////////////////////////////
// functions for UI elements
///////////////////////////////
function signin() {
    client.createSigninRequest({ state: { bar: 15 } }).then(function(req) {
        log("signin request", req, "<a href='" + req.url + "'>go signin</a>");
		openurl(req.url);
    }).catch(function(err) {
        log(err);
    });
}

var signinResponse;
function processSigninResponse() {
	return new Promise(function (resolve, reject) {
		client.processSigninResponse().then(function(response) {
			log("signin response", response);
			resolve(response);
		}).catch(function(err) {
			reject(err);
		});
	});
}

function signout() {
    client.createSignoutRequest({ id_token_hint: signinResponse && signinResponse.id_token, state: { foo: 5 } }).then(function(req) {
        log("signout request", req, "<a href='" + req.url + "'>go signout</a>");
		openurl(req.url);
    });
}

function processSignoutResponse() {
    client.processSignoutResponse().then(function(response) {
        signinResponse = null;
        log("signout response", response);
    }).catch(function(err) {
        log(err);
    });
}

async function doAuthentication() {
	
	var settingsOutput = await makeRequest("GET","./?getConfig");
	var settings = JSON.parse(settingsOutput);
	console.log(settings);
	client = new Oidc.OidcClient(settings.oidc);

	if (window.location.href.indexOf("#") >= 0) {
		signinResponse = await processSigninResponse();
		sessionStorage.setItem('_userInfo',JSON.stringify(signinResponse));
		window.location = "./";
	} else if (window.location.href.indexOf("?") >= 0) {
		processSignoutResponse();
	}
	
	var _userInfo = sessionStorage.getItem('_userInfo');
	if(_userInfo) {
		signinResponse = JSON.parse(_userInfo);
		//console.log(signinResponse);
		
		document.querySelector("#displayname").innerHTML = signinResponse.profile.given_name;
		var pwd = document.querySelector("#passwordentry");
		pwd.removeAttribute('readonly');
		pwd.removeAttribute('placeholder');
		
		if(settings.haveToken) {
			renderAppList(settings);
		}
		//console.log(document.querySelector("#displayname"));
		//log(signinResponse);
	} else {
		log("Waiting for login");
		
	}
	var _didSignin = sessionStorage.getItem('_didSignin');
	if(!_didSignin) {
		sessionStorage.setItem('_didSignin','true');
		signin();
	}	
}

function renderAppList(resultObj) {
	var pwd = document.querySelector("#passwordentry");
	var UI = document.querySelector("#UI");
	
	pwd.value="";
	document.querySelector("#logonUI").style.display = 'none';
	//echo '<a class="rr" href="/?removetoken"><span class="iconify" data-icon="mdi-shield-lock" title="Logoff for apps">lock</span></a>';
	var closeLink = document.createElement('a');
	closeLink.className = "rr";
	closeLink.href="javascript:deleteToken();";
	var closeIcon = document.createElement('span');
	closeIcon.className='iconify';
	closeIcon.setAttribute('data-icon','mdi-shield-lock');
	closeIcon.title="Logoff for apps";
	closeIcon.appendChild(document.createTextNode("lock"));
	closeLink.appendChild(closeIcon);
	UI.appendChild(closeLink);
	
	resultObj.apps.forEach(function(app) {
		//echo '<a class="ll" href="/?open='.$name.'" target="__'.$name.'" title="'.$name.'"><div class="app"><div><span class="iconify" data-icon="'.$conf['parameters']['icon'].'">'.$name.'</span></div>'.$name.'</div></a>';
		var appLink = document.createElement('a');
		appLink.className = "ll";
		//appLink.target = "APP_"+app.name;
		appLink.href="javascript:openApp('"+app.name+"');";
		appLink.title = app.name;
		var outerDiv = document.createElement('div');
		outerDiv.className = "app";
		appLink.appendChild(outerDiv);
		var appIcon = document.createElement('span');
		appIcon.className='iconify';
		appIcon.setAttribute('data-icon',app.icon);
		outerDiv.appendChild(appIcon);
		
		UI.appendChild(appLink);
		//console.log(app);
	});	
}


async function createNewToken() {
	var pwd = document.querySelector("#passwordentry");
	var UI = document.querySelector("#UI");
	pwd.disabled = true;
	var fd = new FormData();
	fd.set('data', JSON.stringify({'token': signinResponse,'pwd': pwd.value}));
	var result = await makeRequest("POST","./?createToken",fd);
	//console.log(result);
	var resultObj = JSON.parse(result);
	if(resultObj.status=='ok') {
		renderAppList(resultObj);
	} else {
		alert("Error: "+resultObj.message);
	}
	pwd.disabled = false;
}

doAuthentication();


