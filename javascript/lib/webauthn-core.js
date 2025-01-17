/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

"use strict";

import base64url from "./base64url.js";
import http from "./http.js";
import abortController from "./abort-controller.js";

async function isConditionalMediationAvailable() {
  return !!(
    window.PublicKeyCredential &&
    window.PublicKeyCredential.isConditionalMediationAvailable &&
    (await window.PublicKeyCredential.isConditionalMediationAvailable())
  );
}

async function authenticate(headers, contextPath, useConditionalMediation) {
  let options;
  try {
    const optionsResponse = await http.post(`${contextPath}/webauthn/authenticate/options`, headers);
    if (!optionsResponse.ok) {
      throw new Error(`HTTP ${optionsResponse.status}`);
    }
    options = await optionsResponse.json();
  } catch (err) {
    throw new Error(`Authentication failed. Could not fetch authentication options: ${err.message}`, { cause: err });
  }

  // FIXME: Use https://www.w3.org/TR/webauthn-3/#sctn-parseRequestOptionsFromJSON
  const decodedAllowCredentials = !options.allowCredentials
    ? []
    : options.allowCredentials.map((cred) => ({
        ...cred,
        id: base64url.decode(cred.id),
      }));

  const decodedOptions = {
    ...options,
    allowCredentials: decodedAllowCredentials,
    challenge: base64url.decode(options.challenge),
  };

  // Invoke the WebAuthn get() method.
  const credentialOptions = {
    publicKey: decodedOptions,
    signal: abortController.newSignal(),
  };
  if (useConditionalMediation) {
    // Request a conditional UI
    credentialOptions.mediation = "conditional";
  }

  let cred;
  try {
    cred = await navigator.credentials.get(credentialOptions);
  } catch (err) {
    throw new Error(`Authentication failed. Call to navigator.credentials.get failed: ${err.message}`, { cause: err });
  }

  const { response, type: credType } = cred;
  let userHandle;
  if (response.userHandle) {
    userHandle = base64url.encode(response.userHandle);
  }
  const body = {
    id: cred.id,
    rawId: base64url.encode(cred.rawId),
    response: {
      authenticatorData: base64url.encode(response.authenticatorData),
      clientDataJSON: base64url.encode(response.clientDataJSON),
      signature: base64url.encode(response.signature),
      userHandle,
    },
    credType,
    clientExtensionResults: cred.getClientExtensionResults(),
    authenticatorAttachment: cred.authenticatorAttachment,
  };

  let authenticationResponse;
  try {
    const authenticationCallResponse = await http.post(`${contextPath}/login/webauthn`, headers, body);
    if (!authenticationCallResponse.ok) {
      throw new Error(`HTTP ${authenticationCallResponse.status}`);
    }
    authenticationResponse = await authenticationCallResponse.json();
    //   if (authenticationResponse && authenticationResponse.authenticated) {
  } catch (err) {
    throw new Error(`Authentication failed. Could not process the authentication request: ${err.message}`, {
      cause: err,
    });
  }

  if (!(authenticationResponse && authenticationResponse.authenticated && authenticationResponse.redirectUrl)) {
    throw new Error(
      `Authentication failed. Expected {"authenticated": true, "redirectUrl": "..."}, server responded with: ${JSON.stringify(authenticationResponse)}`,
    );
  }

  return authenticationResponse.redirectUrl;
}

async function register(headers, contextPath, label) {
  if (!label) {
    throw new Error("Error: Passkey Label is required");
  }

  let options;
  try {
    const optionsResponse = await http.post(`${contextPath}/webauthn/register/options`, headers);
    if (!optionsResponse.ok) {
      throw new Error(`Server responded with HTTP ${optionsResponse.status}`);
    }
    options = await optionsResponse.json();
  } catch (e) {
    throw new Error(`Registration failed. Could not fetch registration options: ${e.message}`, { cause: e });
  }

  // FIXME: Use https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON
  const decodedExcludeCredentials = !options.excludeCredentials
    ? []
    : options.excludeCredentials.map((cred) => ({
        ...cred,
        id: base64url.decode(cred.id),
      }));

  const decodedOptions = {
    ...options,
    user: {
      ...options.user,
      id: base64url.decode(options.user.id),
    },
    challenge: base64url.decode(options.challenge),
    excludeCredentials: decodedExcludeCredentials,
  };

  let credentialsContainer;
  try {
    credentialsContainer = await navigator.credentials.create({
      publicKey: decodedOptions,
      signal: abortController.newSignal(),
    });
  } catch (e) {
    throw new Error(`Registration failed. Call to navigator.credentials.create failed: ${e.message}`, { cause: e });
  }

  // FIXME: Let response be credential.response. If response is not an instance of AuthenticatorAttestationResponse, abort the ceremony with a user-visible error. https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
  const { response } = credentialsContainer;
  const credential = {
    id: credentialsContainer.id,
    rawId: base64url.encode(credentialsContainer.rawId),
    response: {
      attestationObject: base64url.encode(response.attestationObject),
      clientDataJSON: base64url.encode(response.clientDataJSON),
      transports: response.getTransports ? response.getTransports() : [],
    },
    type: credentialsContainer.type,
    clientExtensionResults: credentialsContainer.getClientExtensionResults(),
    authenticatorAttachment: credentialsContainer.authenticatorAttachment,
  };

  const registrationRequest = {
    publicKey: {
      credential: credential,
      label: label,
    },
  };

  let verificationJSON;
  try {
    const verificationResp = await http.post(`${contextPath}/webauthn/register`, headers, registrationRequest);
    if (!verificationResp.ok) {
      throw new Error(`HTTP ${verificationResp.status}`);
    }
    verificationJSON = await verificationResp.json();
  } catch (e) {
    throw new Error(`Registration failed. Could not process the registration request: ${e.message}`, { cause: e });
  }

  if (!(verificationJSON && verificationJSON.success)) {
    throw new Error(`Registration failed. Server responded with: ${JSON.stringify(verificationJSON)}`);
  }
}

export default {
  authenticate,
  register,
  isConditionalMediationAvailable,
};
