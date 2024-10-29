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
 * <a href="https://www.w3.org/TR/webauthn-3/#iface-pkcredential">PublicKeyCredential</a>
 * contains the attributes that are returned to the caller when a new credential is
 * created, or a new assertion is requested.
 *
 * @author Rob Winch
 * @since 6.4
 */
public final class PublicKeyCredential<R extends AuthenticatorResponse> {

	private final String id;

	private final PublicKeyCredentialType type;

	private final Bytes rawId;

	private final R response;

	private final AuthenticatorAttachment authenticatorAttachment;

	private final AuthenticationExtensionsClientOutputs clientExtensionResults;

	private PublicKeyCredential(String id, PublicKeyCredentialType type, Bytes rawId, R response,
			AuthenticatorAttachment authenticatorAttachment,
			AuthenticationExtensionsClientOutputs clientExtensionResults) {
		this.id = id;
		this.type = type;
		this.rawId = rawId;
		this.response = response;
		this.authenticatorAttachment = authenticatorAttachment;
		this.clientExtensionResults = clientExtensionResults;
	}

	/**
	 * The
	 * <a href="https://www.w3.org/TR/credential-management-1/#dom-credential-id">id</a>
	 * attribute is inherited from Credential, though PublicKeyCredential overrides
	 * Credential's getter, instead returning the base64url encoding of the data contained
	 * in the object's [[identifier]] internal slot.
	 */
	public String getId() {
		return this.id;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/credential-management-1/#dom-credential-type">type</a>
	 * attribute returns the value of the object's interface object's [[type]] slot, which
	 * specifies the credential type represented by this object.
	 * @return the credential type
	 */
	public PublicKeyCredentialType getType() {
		return this.type;
	}

	/**
	 * The
	 * <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-rawid">rawId</a>
	 * returns the raw identifier.
	 * @return the raw id
	 */
	public Bytes getRawId() {
		return this.rawId;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response">response</a>
	 * to the client's request to either create a public key credential, or generate an
	 * authentication assertion.
	 * @return the response
	 */
	public R getResponse() {
		return this.response;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-authenticatorattachment">authenticatorAttachment</a>
	 * reports the <a href=
	 * "https://www.w3.org/TR/webauthn-3/#authenticator-attachment-modality">authenticator
	 * attachment modality</a> in effect at the time the navigator.credentials.create() or
	 * navigator.credentials.get() methods successfully complete.
	 * @return the authenticator attachment
	 */
	public AuthenticatorAttachment getAuthenticatorAttachment() {
		return this.authenticatorAttachment;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-getclientextensionresults">clientExtensionsResults</a>
	 * is a mapping of extension identifier to client extension output.
	 * @return the extension results
	 */
	public AuthenticationExtensionsClientOutputs getClientExtensionResults() {
		return this.clientExtensionResults;
	}

	/**
	 * Creates a new {@link PublicKeyCredentialBuilder}
	 * @param <T> the response type
	 * @return the {@link PublicKeyCredentialBuilder}
	 */
	public static <T extends AuthenticatorResponse> PublicKeyCredentialBuilder<T> builder() {
		return new PublicKeyCredentialBuilder<>();
	}

	/**
	 * The {@link PublicKeyCredentialBuilder}
	 *
	 * @param <R> the response type
	 * @author Rob Winch
	 * @since 6.4
	 */
	public static final class PublicKeyCredentialBuilder<R extends AuthenticatorResponse> {

		private String id;

		private PublicKeyCredentialType type;

		private Bytes rawId;

		private R response;

		private AuthenticatorAttachment authenticatorAttachment;

		private AuthenticationExtensionsClientOutputs clientExtensionResults;

		private PublicKeyCredentialBuilder() {
		}

		/**
		 * Sets the {@link #getId()} property
		 * @param id the id
		 * @return the PublicKeyCredentialBuilder
		 */
		public PublicKeyCredentialBuilder id(String id) {
			this.id = id;
			return this;
		}

		/**
		 * Sets the {@link #getType()} property.
		 * @param type the type
		 * @return the PublicKeyCredentialBuilder
		 */
		public PublicKeyCredentialBuilder type(PublicKeyCredentialType type) {
			this.type = type;
			return this;
		}

		/**
		 * Sets the {@link #getRawId()} property.
		 * @param rawId the raw id
		 * @return the PublicKeyCredentialBuilder
		 */
		public PublicKeyCredentialBuilder rawId(Bytes rawId) {
			this.rawId = rawId;
			return this;
		}

		/**
		 * Sets the {@link #getResponse()} property.
		 * @param response the response
		 * @return the PublicKeyCredentialBuilder
		 */
		public PublicKeyCredentialBuilder response(R response) {
			this.response = response;
			return this;
		}

		/**
		 * Sets the {@link #getAuthenticatorAttachment()} property.
		 * @param authenticatorAttachment the authenticator attachement
		 * @return the PublicKeyCredentialBuilder
		 */
		public PublicKeyCredentialBuilder authenticatorAttachment(AuthenticatorAttachment authenticatorAttachment) {
			this.authenticatorAttachment = authenticatorAttachment;
			return this;
		}

		/**
		 * Sets the {@link #getClientExtensionResults()} property.
		 * @param clientExtensionResults the client extension results
		 * @return the PublicKeyCredentialBuilder
		 */
		public PublicKeyCredentialBuilder clientExtensionResults(
				AuthenticationExtensionsClientOutputs clientExtensionResults) {
			this.clientExtensionResults = clientExtensionResults;
			return this;
		}

		/**
		 * Creates a new {@link PublicKeyCredential}
		 * @return a new {@link PublicKeyCredential}
		 */
		public PublicKeyCredential<R> build() {
			return new PublicKeyCredential(this.id, this.type, this.rawId, this.response, this.authenticatorAttachment,
					this.clientExtensionResults);
		}

	}

}
