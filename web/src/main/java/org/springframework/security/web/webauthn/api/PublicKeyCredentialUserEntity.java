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

package org.springframework.security.web.webauthn.api;

/**
 * <a href=
 * "https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity">PublicKeyCredentialUserEntity</a>
 * is used to supply additional
 * <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> attributes
 * when creating a new credential.
 *
 * @author Rob Winch
 * @since 6.4
 * @see org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations#authenticate(org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest)
 */
public interface PublicKeyCredentialUserEntity {

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialentity-name">name</a>
	 * property is a human-palatable identifier for a user account.
	 * @return the name
	 */
	String getName();

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id">id</a> is
	 * the user handle of the user account. A user handle is an opaque byte sequence with
	 * a maximum size of 64 bytes, and is not meant to be displayed to the user.
	 * @return the user handle of the user account
	 */
	Bytes getId();

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-displayname">displayName</a>
	 * is a human-palatable name for the user account, intended only for display.
	 * @return the display name
	 */
	String getDisplayName();

}
