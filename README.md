# guacamole-openid-gateway
Glue project between Azure AD and guacamole with guacamole-auth-json


Can be embedded into workspace 365 with the following embed code:
```{html}
<form name="autologon" class="loginform" method="post" action="https://URL-WHERE-YOU-INSTALLED-GATEWAY.COM" title="Unlocking..." >
	<a href="javascript: document.autologon.submit();">
		<div class="shield">
			<span class="iconify largeicon" data-icon="mdi-refresh">Unlocking...</span>
		</div>
		<input type="hidden" name="login" value="true" />
		Click here if authentication window did not open.
		<script>document.autologon.submit();</script>
	</a>
</form>
```
