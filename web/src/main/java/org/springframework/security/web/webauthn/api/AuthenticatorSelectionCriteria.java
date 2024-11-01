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
 * "https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorselectioncriteria">AuthenticatorAttachment</a>
 * can be used by
 * <a href="https://www.w3.org/TR/webauthn-3/#webauthn-relying-party">WebAuthn Relying
 * Parties</a> to specify their requirements regarding authenticator attributes.
 *
 * There is no <a href=
 * "https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-requireresidentkey">requireResidentKey</a>
 * property because it is only for backwards compatibility with WebAuthn Level 1.
 *
 * @author Rob Winch
 * @since 6.4
 * @see PublicKeyCredentialCreationOptions#getAuthenticatorSelection()
 */
public final class AuthenticatorSelectionCriteria {

	private final AuthenticatorAttachment authenticatorAttachment;

	private final ResidentKeyRequirement residentKey;

	private final UserVerificationRequirement userVerification;

	// NOTE: There is no requireResidentKey property because it is only for backward
	// compatibility with WebAuthn Level 1

	/**
	 * Creates a new instance
	 * @param authenticatorAttachment the authenticator attachment
	 * @param residentKey the resident key requirement
	 * @param userVerification the user verification
	 */
	private AuthenticatorSelectionCriteria(AuthenticatorAttachment authenticatorAttachment,
			ResidentKeyRequirement residentKey, UserVerificationRequirement userVerification) {
		this.authenticatorAttachment = authenticatorAttachment;
		this.residentKey = residentKey;
		this.userVerification = userVerification;
	}

	/**
	 * If <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-authenticatorattachment">
	 * authenticatorAttachment</a> is present, eligible
	 * <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticators</a> are
	 * filtered to be only those authenticators attached with the specified
	 * <a href="https://www.w3.org/TR/webauthn-3/#enum-attachment">authenticator
	 * attachment modality</a> (see also <a href=
	 * "https://www.w3.org/TR/webauthn-3/#sctn-authenticator-attachment-modality">6.2.1
	 * Authenticator Attachment Modality</a>).
	 * @return the authenticator attachment
	 */
	public AuthenticatorAttachment getAuthenticatorAttachment() {
		return this.authenticatorAttachment;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-residentkey">residentKey</a>
	 * specifies the extent to which the
	 * <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> desires
	 * to create a <a href=
	 * "https://www.w3.org/TR/webauthn-3/#client-side-discoverable-credential">client-side
	 * discoverable credential</a>.
	 * @return the resident key requirement
	 */
	public ResidentKeyRequirement getResidentKey() {
		return this.residentKey;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-userverification">userVerification</a>
	 * specifies the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying
	 * Party</a>'s requirements regarding
	 * <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a>
	 * for the <a href=
	 * "https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a>
	 * operation.
	 * @return the user verification requirement
	 */
	public UserVerificationRequirement getUserVerification() {
		return this.userVerification;
	}

	/**
	 * Creates a new {@link AuthenticatorSelectionCriteriaBuilder}
	 * @return a new {@link AuthenticatorSelectionCriteriaBuilder}
	 */
	public static AuthenticatorSelectionCriteriaBuilder builder() {
		return new AuthenticatorSelectionCriteriaBuilder();
	}

	/**
	 * Creates a {@link AuthenticatorSelectionCriteria}
	 *
	 * @author Rob Winch
	 * @since 6.4
	 */
	public static final class AuthenticatorSelectionCriteriaBuilder {

		private AuthenticatorAttachment authenticatorAttachment;

		private ResidentKeyRequirement residentKey;

		private UserVerificationRequirement userVerification;

		private AuthenticatorSelectionCriteriaBuilder() {
		}

		/**
		 * Sets the {@link #getAuthenticatorAttachment()} property.
		 * @param authenticatorAttachment the authenticator attachment
		 * @return the {@link AuthenticatorSelectionCriteriaBuilder}
		 */
		public AuthenticatorSelectionCriteriaBuilder authenticatorAttachment(
				AuthenticatorAttachment authenticatorAttachment) {
			this.authenticatorAttachment = authenticatorAttachment;
			return this;
		}

		/**
		 * Sets the {@link #getResidentKey()} property.
		 * @param residentKey the resident key
		 * @return the {@link AuthenticatorSelectionCriteriaBuilder}
		 */
		public AuthenticatorSelectionCriteriaBuilder residentKey(ResidentKeyRequirement residentKey) {
			this.residentKey = residentKey;
			return this;
		}

		/**
		 * Sets the {@link #getUserVerification()} property.
		 * @param userVerification the user verification requirement
		 * @return the {@link AuthenticatorSelectionCriteriaBuilder}
		 */
		public AuthenticatorSelectionCriteriaBuilder userVerification(UserVerificationRequirement userVerification) {
			this.userVerification = userVerification;
			return this;
		}

		/**
		 * Builds a {@link AuthenticatorSelectionCriteria}
		 * @return a new {@link AuthenticatorSelectionCriteria}
		 */
		public AuthenticatorSelectionCriteria build() {
			return new AuthenticatorSelectionCriteria(this.authenticatorAttachment, this.residentKey,
					this.userVerification);
		}

	}

}
