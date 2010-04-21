var claimedID;
var providerID;
var openIDPopup;

function OpenID_iframe_then_popup_handler(provider, claimed) {
    providerID = provider;
    claimedID = claimed;
    var immediateiframe = document.getElementById("openid_immediate_iframe");

    var iframeurl = getBaseOpenIDProviderURL(providerID, claimedID, true);
    
    immediateiframe.innerHTML = "<iframe frameborder='1' src='" + iframeurl + "'></iframe>";
}

function processOpenIDImmediateResponse(responseURL) {
	var immediateiframe = document.getElementById("openid_immediate_iframe");
	immediateiframe.innerHTML = responseURL;

	var failure = new RegExp("openid.mode=setup_needed");
	if(failure.test(responseURL)) {
		var popupurl = getBaseOpenIDProviderURL(providerID, claimedID, false);
        openIDPopup = window.open(popupurl, "OpenIDPopup");
	} else {
	    alert("Success without popup!");
	}
}

function processOpenIDSetupResponse(responseURL) {
	openIDPopup.close();

	var results = "";
	var responseQuery = $.query.load(responseURL);
    $.each(responseQuery.get(), function(key, value) {
         results += "<br/>" + key + "=" + value;
    });

    document.getElementById("openid_status").innerHTML = "<br/>Result of authentication is: " + results;
}

function getBaseOpenIDProviderURL(provider, claimed, immediate) {
	var providerEndpoint = providers_endpoint[provider];
    var providerURL = providerEndpoint; //From previous discovery
    providerURL += "?";
    providerURL += "openid.ns=" + encodeURIComponent("http://specs.openid.net/auth/2.0");
    if(providers[provider].label) {
        providerURL += "&openid.claimed_id=" + encodeURIComponent(claimed);
        providerURL += "&openid.identity=" + encodeURIComponent(claimed);    	
    }
    else {
        providerURL += "&openid.claimed_id=" + encodeURIComponent("http://specs.openid.net/auth/2.0/identifier_select");
        providerURL += "&openid.identity=" + encodeURIComponent("http://specs.openid.net/auth/2.0/identifier_select");
    }
    if(immediate) {
        providerURL += "&openid.return_to=" + encodeURIComponent(server_root + "openid-client/checkid_immediate_response.html");
        providerURL += "&openid.realm=" + encodeURIComponent(server_root + "openid-client/checkid_immediate_response.html");
        providerURL += "&openid.mode=checkid_immediate";
    } else {
        providerURL += "&openid.return_to=" + encodeURIComponent(server_root + "openid-client/checkid_setup_response.html");
        providerURL += "&openid.realm=" + encodeURIComponent(server_root + "openid-client/checkid_setup_response.html");
        providerURL += "&openid.mode=checkid_setup";
    }
    return providerURL;
}