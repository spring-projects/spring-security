
function createCredential(residentKeyRequirement){

    var username = $("#username").val();
    var userHandle = $("#userHandle").val();
    var challenge = $("meta[name=webAuthnChallenge]").attr("content");
    var credentialIds = $("meta[name=webAuthnCredentialId]")
        .map(function(i, element){ return $(element).attr("content")})
        .get();

    var publicKeyCredentialCreationOptions = {
        rp: {
            name: "Spring Security WebAuthn Sample"
        },
        user: {
            id: base64url.decodeBase64url(userHandle),
            name: username,
            displayName: username
        },
        challenge: base64url.decodeBase64url(challenge),
        pubKeyCredParams: [
            {
                "type": "public-key",
                "alg": -7 //ES256
            },
            {
                type: "public-key",
                alg: -257 //RS256
            }
        ],
        excludeCredentials: credentialIds.map(function(credentialId){
            return {
                type: "public-key",
                id: base64url.decodeBase64url(credentialId)
            }
        }),
        authenticatorSelection: {
            requireResidentKey: residentKeyRequirement
        },
        attestation: "none"
    };

    var credentialCreationOptions = {
        publicKey: publicKeyCredentialCreationOptions
    };

    return navigator.credentials.create(credentialCreationOptions);
}

function getCredential(userVerification){
    var challenge = $("meta[name=webAuthnChallenge]").attr("content");
    var credentialIds = $("meta[name=webAuthnCredentialId]")
        .map(function(i, element){ return $(element).attr("content")})
        .get();
    var publicKeyCredentialRequestOptions = {
        challenge: base64url.decodeBase64url(challenge),
        allowCredentials: credentialIds.map(function(credentialId){
            return {
                type: "public-key",
                id: base64url.decodeBase64url(credentialId)
            }
        }),
        userVerification: userVerification
    };

    var credentialRequestOptions = {
        publicKey: publicKeyCredentialRequestOptions
    };

    return navigator.credentials.get(credentialRequestOptions);
}

$(document).ready(function() {

    var dialog = $("#resident-key-requirement-dialog");

    var onResidentKeyRequirementDialogClosing = function(residentKeyRequirement){
        createCredential(residentKeyRequirement).then(function (credential) {
            console.log(credential);
            $('#clientDataJSON').val(base64url.encodeBase64url(credential.response.clientDataJSON));
            $('#attestationObject').val(base64url.encodeBase64url(credential.response.attestationObject));
            $('#clientExtensions').val(JSON.stringify(credential.getClientExtensionResults()));
            $('#authenticator').text('Authenticator registered');
            $('#authenticator').prop('disabled', true);
            $('#submit').prop('disabled', false);
            dialog.modal('hide');
        }).catch(function (e) {
            console.error("Error:%s, Message:%s", e.name, e.message);
            dialog.modal('hide');
        });
    };

    $('#resident-key-requirement-dialog-yes').click(function () {
        onResidentKeyRequirementDialogClosing(true);
    });
    $('#resident-key-requirement-dialog-no').click(function () {
        onResidentKeyRequirementDialogClosing(false);
    });
    $('#resident-key-requirement-dialog-close').click(function () {
        dialog.modal('hide');
    });

    $('#authenticator').click(function(){
        dialog.modal('show');
    });

    $('#fast-login').click(function(){
        getCredential("required").then(function (credential) {
            console.log(credential);
            $("#credentialId").val(credential.id);
            $("#clientDataJSON").val(base64url.encodeBase64url(credential.response.clientDataJSON));
            $("#authenticatorData").val(base64url.encodeBase64url(credential.response.authenticatorData));
            $("#signature").val(base64url.encodeBase64url(credential.response.signature));
            $("#clientExtensions").val(JSON.stringify(credential.getClientExtensionResults()));
            $('#login-form').submit();
        }).catch(function (e) {
            console.error("Error:%s, Message:%s", e.name, e.message);
        });
        return false;
    });
    $('#retry').click(function(){
        getCredential("preferred").then(function (credential) {
            console.log(credential);
            $("#credentialId").val(credential.id);
            $("#clientDataJSON").val(base64url.encodeBase64url(credential.response.clientDataJSON));
            $("#authenticatorData").val(base64url.encodeBase64url(credential.response.authenticatorData));
            $("#signature").val(base64url.encodeBase64url(credential.response.signature));
            $("#clientExtensions").val(JSON.stringify(credential.getClientExtensionResults()));
            $('#login-form').submit();
        }).catch(function (e) {
            console.error("Error:%s, Message:%s", e.name, e.message);
        });
        return false;
    });

    if($('#login-authenticator-login-view').length>0){
        return getCredential("preferred").then(function (credential) {
            console.log(credential);
            $("#credentialId").val(credential.id);
            $("#clientDataJSON").val(base64url.encodeBase64url(credential.response.clientDataJSON));
            $("#authenticatorData").val(base64url.encodeBase64url(credential.response.authenticatorData));
            $("#signature").val(base64url.encodeBase64url(credential.response.signature));
            $("#clientExtensions").val(JSON.stringify(credential.getClientExtensionResults()));
            $('#login-form').submit();
        }).catch(function (e) {
            console.error("Error:%s, Message:%s", e.name, e.message);
        });
    }
});
