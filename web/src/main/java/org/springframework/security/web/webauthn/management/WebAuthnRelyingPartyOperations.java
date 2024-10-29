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

package org.springframework.security.web.webauthn.management;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;

/**
 * An API for <a href="https://www.w3.org/TR/webauthn-3/#sctn-rp-operations">WebAuthn
 * Relying Party Operations</a>
 *
 * @author Rob Winch
 * @since 6.4
 */
public interface WebAuthnRelyingPartyOperations {

	/**
	 * Creates the {@link PublicKeyCredentialCreationOptions} used to register new
	 * credentials.
	 * @param request the {@link PublicKeyCredentialCreationOptionsRequest} to create the
	 * {@link PublicKeyCredentialCreationOptions}
	 * @return the {@link PublicKeyCredentialCreationOptions} for the
	 * {@link Authentication} passed in. Cannot be null.
	 */
	PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(
			PublicKeyCredentialCreationOptionsRequest request);

	/**
	 * If {@link RelyingPartyRegistrationRequest} is valid, will <a href=
	 * "https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">register</a>
	 * and return a new {@link CredentialRecord}.
	 * @param relyingPartyRegistrationRequest the {@link RelyingPartyRegistrationRequest}
	 * to process.
	 * @return a new {@link CredentialRecord}
	 * @throws RuntimeException if the {@link RelyingPartyRegistrationRequest} is not
	 * valid.
	 */
	CredentialRecord registerCredential(RelyingPartyRegistrationRequest relyingPartyRegistrationRequest);

	/**
	 * Creates the {@link PublicKeyCredentialRequestOptions} used to authenticate a user.
	 * @param request the {@link PublicKeyCredentialRequestOptionsRequest}.
	 * @return the {@link PublicKeyCredentialRequestOptions} used to authenticate a user.
	 */
	PublicKeyCredentialRequestOptions createCredentialRequestOptions(PublicKeyCredentialRequestOptionsRequest request);

	/**
	 * Authenticates the {@link RelyingPartyAuthenticationRequest} passed in
	 * @param request the {@link RelyingPartyAuthenticationRequest}
	 * @return the principal name (e.g. username) if authentication was successful
	 * @throws RuntimeException if authentication fails
	 */
	PublicKeyCredentialUserEntity authenticate(RelyingPartyAuthenticationRequest request);

}
