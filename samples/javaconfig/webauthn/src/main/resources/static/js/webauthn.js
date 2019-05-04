
function createCredential(residentKeyRequirement){

    return fetchAttestationOptions().then(function (options) {
        var username = $("#username").val();
        var userHandle = $("#userHandle").val();

        var authenticatorSelection = options["authenticatorSelection"];
        authenticatorSelection["requireResidentKey"] = residentKeyRequirement;
        var publicKeyCredentialCreationOptions = {
            rp: options["rp"],
            user: {
                id: base64url.decodeBase64url(userHandle),
                name: username,
                displayName: username
            },
            challenge: base64url.decodeBase64url(options["challenge"]),
            pubKeyCredParams: options["pubKeyCredParams"],
            timeout: options["timeout"],
            excludeCredentials: options["excludeCredentials"].map(function(credential){
                return {
                    type: credential["type"],
                    id: base64url.decodeBase64url(credential["id"])
                }
            }),
            authenticatorSelection: authenticatorSelection,
            attestation: options["attestation"],
            extensions: options["extensions"]
        };

        var credentialCreationOptions = {
            publicKey: publicKeyCredentialCreationOptions
        };

        return navigator.credentials.create(credentialCreationOptions);
    });
}

function getCredential(userVerification){
    return fetchAssertionOptions().then(function (options) {
        var publicKeyCredentialRequestOptions = {
            challenge: base64url.decodeBase64url(options["challenge"]),
            timeout:  options["timeout"],
            rpId: options["rpId"],
            allowCredentials: options["allowCredentials"].map(function(credential){
                return {
                    type: credential["type"],
                    id: base64url.decodeBase64url(credential["id"])
                }
            }),
            userVerification: userVerification,
            extensions: options["extensions"]
        };

        var credentialRequestOptions = {
            publicKey: publicKeyCredentialRequestOptions
        };

        return navigator.credentials.get(credentialRequestOptions);
    });
}

function fetchAttestationOptions(){
    return $.ajax({
        type: 'GET',
        url: './webauthn/attestation/options',
        dataType: 'json'
    }).done(function(options){
        console.log(options);
        return options;
    }).fail(function(error){
        console.log(error);
    });
}

function fetchAssertionOptions(){
    return $.ajax({
        type: 'GET',
        url: './webauthn/assertion/options',
        dataType: 'json'
    }).done(function(options){
        console.log(options);
        return options;
    }).fail(function(error){
        console.log(error);
    });
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
