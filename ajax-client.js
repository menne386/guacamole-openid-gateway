

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

async function main() {
	
	var settingsOutput = await makeRequest("GET","/?getConfig");
	var settings = JSON.parse(settingsOutput);
	console.log(settings);
	
	var logonUI = document.querySelector("#logonUI");
	var pwd = document.querySelector("#passwordentry");
	var displayName = document.querySelector("#displayname");

	if(settings.haveUser) {
		displayName.innerHTML = settings.displayname;
		
		pwd.removeAttribute('readonly');
		pwd.removeAttribute('placeholder');
		
		logonUI.onsubmit = function(){
			createNewToken();
			return false;
		}
	} else {
		pwd.style.display = "none";
		logonUI.title = "Click to authenticate with Microsoft";
		logonUI.target = "__logonTab";
		var hiddenLogon = document.createElement('input');
		hiddenLogon.type="hidden";
		hiddenLogon.name="login";
		hiddenLogon.value="newTab";
		logonUI.appendChild(hiddenLogon);
		logonUI.onclick = function() {
			logonUI.submit();
		}
	}
	
	if(settings.haveToken) {
		renderAppList(settings);
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
	closeLink.onclick = deleteToken;
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
		appLink.href= app.url;
		appLink.title = app.name;
		appLink.target = "App_"+app.name;
		
		var outerDiv = document.createElement('div');
		outerDiv.className = "app";
		appLink.appendChild(outerDiv);
		var appIcon = document.createElement('span');
		appIcon.className='iconify';
		appIcon.setAttribute('data-icon',app.icon);
		outerDiv.appendChild(appIcon);
		
		UI.appendChild(appLink);
		console.log(app);
	});

	openSession();
	setInterval(openSession,30000);
}


async function createNewToken() {
	var pwd = document.querySelector("#passwordentry");
	pwd.disabled = true;
	var fd = new FormData();
	fd.set('pwd',  pwd.value);
	var result = await makeRequest("POST","/?createToken",fd);
	//console.log(result);
	var resultObj = JSON.parse(result);
	if(resultObj.status=='ok') {
		renderAppList(resultObj);
	} else {
		alert("Error: "+resultObj.message);
	}
	pwd.disabled = false;
}

async function openSession() {
	//alert("Would have opened "+appName);
	var fd = new FormData();
	var GT = localStorage.getItem('GUAC_AUTH');
	if(GT) {
		//We already have a guac authToken: send it with the request:
		var gtObj = JSON.parse(GT);
		fd.set('authToken', gtObj.authToken);
	}
	var result = await makeRequest("POST","/?openSession",fd);
	var resultObj = JSON.parse(result);
	//console.log(resultObj);
	if(resultObj.status=='ok') {
		if(resultObj.GT) {
			localStorage.setItem('GUAC_AUTH',resultObj.GT);
		}
	} else {
		console.log(resultObj);
		deleteToken();
	}
	return false;
}

async function deleteToken() {
	alert("Would have deleted token now");
}

main();


