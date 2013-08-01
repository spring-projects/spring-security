/*
Defines the base of where the OpenID Provider redirects its response to.
 */
var server_root = "http://openid-selector.googlecode.com/svn/trunk/"

/*
On the server-side you'd accept an OpenID URL and perform discovery
on it to find out the actual OpenID endpoint to send the authentication
request to. On the client side it isn't possible to lookup the endpoint
from the target server due to XSS restrictions. The endpoint for each
provider is therefore cached in this static file. If an endpoint isn't 
specified for a provider then authentication on the client side cannot
proceed.
*/
var providers_endpoint = {
	google: 'https://www.google.com/accounts/o8/ud',
	yahoo: 'https://open.login.yahooapis.com/openid/op/auth',
	aol: 'https://api.screenname.aol.com/auth/openidServer',
	verisign: 'http://pip.verisignlabs.com/server'
}