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

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

/**
 * Represents the <a href=
 * "https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions">PublicKeyCredentialCreationOptions</a>
 * which is an argument to <a href=
 * "https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">creating</a>
 * a new credential.
 *
 * @author Rob Winch
 * @since 6.4
 */
public final class PublicKeyCredentialCreationOptions {

	private final PublicKeyCredentialRpEntity rp;

	private final PublicKeyCredentialUserEntity user;

	private final Bytes challenge;

	private final List<PublicKeyCredentialParameters> pubKeyCredParams;

	private final Duration timeout;

	private final List<PublicKeyCredentialDescriptor> excludeCredentials;

	private final AuthenticatorSelectionCriteria authenticatorSelection;

	private final AttestationConveyancePreference attestation;

	private final AuthenticationExtensionsClientInputs extensions;

	private PublicKeyCredentialCreationOptions(PublicKeyCredentialRpEntity rp, PublicKeyCredentialUserEntity user,
			Bytes challenge, List<PublicKeyCredentialParameters> pubKeyCredParams, Duration timeout,
			List<PublicKeyCredentialDescriptor> excludeCredentials,
			AuthenticatorSelectionCriteria authenticatorSelection, AttestationConveyancePreference attestation,
			AuthenticationExtensionsClientInputs extensions) {
		this.rp = rp;
		this.user = user;
		this.challenge = challenge;
		this.pubKeyCredParams = pubKeyCredParams;
		this.timeout = timeout;
		this.excludeCredentials = excludeCredentials;
		this.authenticatorSelection = authenticatorSelection;
		this.attestation = attestation;
		this.extensions = extensions;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-rp">rp</a>
	 * property contains data about the Relying Party responsible for the request.
	 * @return the relying party
	 */
	public PublicKeyCredentialRpEntity getRp() {
		return this.rp;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-user">user</a>
	 * contains names and an identifier for the user account performing the registration.
	 * @return the user
	 */
	public PublicKeyCredentialUserEntity getUser() {
		return this.user;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-challenge">challenge</a>
	 * specifies the challenge that the authenticator signs, along with other data, when
	 * producing an attestation object for the newly created credential.
	 * @return the challenge
	 */
	public Bytes getChallenge() {
		return this.challenge;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-pubkeycredparams">publicKeyCredParams</a>
	 * params lisst the key types and signature algorithms the Relying Party Supports,
	 * ordered from most preferred to least preferred.
	 * @return the public key credential parameters
	 */
	public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
		return this.pubKeyCredParams;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-timeout">timeout</a>
	 * property specifies a time, in milliseconds, that the Relying Party is willing to
	 * wait for the call to complete.
	 * @return the timeout
	 */
	public Duration getTimeout() {
		return this.timeout;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-excludecredentials">excludeCredentials</a>
	 * property is the OPTIONAL member used by the Relying Party to list any existing
	 * credentials mapped to this user account (as identified by user.id).
	 * @return exclude credentials
	 */
	public List<PublicKeyCredentialDescriptor> getExcludeCredentials() {
		return this.excludeCredentials;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-authenticatorselection">authenticatorSelection</a>
	 * property is an OPTIONAL member used by the Relying Party to list any existing
	 * credentials mapped to this user account (as identified by user.id).
	 * @return the authenticatorSelection
	 */
	public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
		return this.authenticatorSelection;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-attestation">attestation</a>
	 * property is an OPTIONAL member used by the Relying Party to specify a preference
	 * regarding attestation conveyance.
	 * @return the attestation preference
	 */
	public AttestationConveyancePreference getAttestation() {
		return this.attestation;
	}

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-extensions">extensions</a>
	 * property is an OPTIONAL member used by the Relying Party to provide client
	 * extension inputs requesting additional processing by the client and authenticator.
	 * @return the extensions
	 */
	public AuthenticationExtensionsClientInputs getExtensions() {
		return this.extensions;
	}

	/**
	 * Creates a new {@link PublicKeyCredentialCreationOptions}
	 * @return a new {@link PublicKeyCredentialCreationOptions}
	 */
	public static PublicKeyCredentialCreationOptionsBuilder builder() {
		return new PublicKeyCredentialCreationOptionsBuilder();
	}

	/**
	 * Used to build {@link PublicKeyCredentialCreationOptions}.
	 *
	 * @author Rob Winch
	 * @since 6.4
	 */
	public static final class PublicKeyCredentialCreationOptionsBuilder {

		private PublicKeyCredentialRpEntity rp;

		private PublicKeyCredentialUserEntity user;

		private Bytes challenge;

		private List<PublicKeyCredentialParameters> pubKeyCredParams = new ArrayList<>();

		private Duration timeout;

		private List<PublicKeyCredentialDescriptor> excludeCredentials = new ArrayList<>();

		private AuthenticatorSelectionCriteria authenticatorSelection;

		private AttestationConveyancePreference attestation;

		private AuthenticationExtensionsClientInputs extensions;

		private PublicKeyCredentialCreationOptionsBuilder() {
		}

		/**
		 * Sets the {@link #getRp()} property.
		 * @param rp the relying party
		 * @return the PublicKeyCredentialCreationOptionsBuilder
		 */
		public PublicKeyCredentialCreationOptionsBuilder rp(PublicKeyCredentialRpEntity rp) {
			this.rp = rp;
			return this;
		}

		/**
		 * Sets the {@link #getUser()} property.
		 * @param user the user entity
		 * @return the PublicKeyCredentialCreationOptionsBuilder
		 */
		public PublicKeyCredentialCreationOptionsBuilder user(PublicKeyCredentialUserEntity user) {
			this.user = user;
			return this;
		}

		/**
		 * Sets the {@link #getChallenge()} property.
		 * @param challenge the challenge
		 * @return the PublicKeyCredentialCreationOptionsBuilder
		 */
		public PublicKeyCredentialCreationOptionsBuilder challenge(Bytes challenge) {
			this.challenge = challenge;
			return this;
		}

		/**
		 * Sets the {@link #getPubKeyCredParams()} property.
		 * @param pubKeyCredParams the public key credential parameters
		 * @return the PublicKeyCredentialCreationOptionsBuilder
		 */
		public PublicKeyCredentialCreationOptionsBuilder pubKeyCredParams(
				PublicKeyCredentialParameters... pubKeyCredParams) {
			return pubKeyCredParams(Arrays.asList(pubKeyCredParams));
		}

		/**
		 * Sets the {@link #getPubKeyCredParams()} property.
		 * @param pubKeyCredParams the public key credential parameters
		 * @return the PublicKeyCredentialCreationOptionsBuilder
		 */
		public PublicKeyCredentialCreationOptionsBuilder pubKeyCredParams(
				List<PublicKeyCredentialParameters> pubKeyCredParams) {
			this.pubKeyCredParams = pubKeyCredParams;
			return this;
		}

		/**
		 * Sets the {@link #getTimeout()} property.
		 * @param timeout the timeout
		 * @return the PublicKeyCredentialCreationOptionsBuilder
		 */
		public PublicKeyCredentialCreationOptionsBuilder timeout(Duration timeout) {
			this.timeout = timeout;
			return this;
		}

		/**
		 * Sets the {@link #getExcludeCredentials()} property.
		 * @param excludeCredentials the excluded credentials.
		 * @return the PublicKeyCredentialCreationOptionsBuilder
		 */
		public PublicKeyCredentialCreationOptionsBuilder excludeCredentials(
				List<PublicKeyCredentialDescriptor> excludeCredentials) {
			this.excludeCredentials = excludeCredentials;
			return this;
		}

		/**
		 * Sets the {@link #getAuthenticatorSelection()} property.
		 * @param authenticatorSelection the authenticator selection
		 * @return the PublicKeyCredentialCreationOptionsBuilder
		 */
		public PublicKeyCredentialCreationOptionsBuilder authenticatorSelection(
				AuthenticatorSelectionCriteria authenticatorSelection) {
			this.authenticatorSelection = authenticatorSelection;
			return this;
		}

		/**
		 * Sets the {@link #getAttestation()} property.
		 * @param attestation the attestation
		 * @return the PublicKeyCredentialCreationOptionsBuilder
		 */
		public PublicKeyCredentialCreationOptionsBuilder attestation(AttestationConveyancePreference attestation) {
			this.attestation = attestation;
			return this;
		}

		/**
		 * Sets the {@link #getExtensions()} property.
		 * @param extensions the extensions
		 * @return the PublicKeyCredentialCreationOptionsBuilder
		 */
		public PublicKeyCredentialCreationOptionsBuilder extensions(AuthenticationExtensionsClientInputs extensions) {
			this.extensions = extensions;
			return this;
		}

		/**
		 * Allows customizing the builder using the {@link Consumer} that is passed in.
		 * @param customizer the {@link Consumer} that can be used to customize the
		 * {@link PublicKeyCredentialCreationOptionsBuilder}
		 * @return the PublicKeyCredentialCreationOptionsBuilder
		 */
		public PublicKeyCredentialCreationOptionsBuilder customize(
				Consumer<PublicKeyCredentialCreationOptionsBuilder> customizer) {
			customizer.accept(this);
			return this;
		}

		/**
		 * Builds a new {@link PublicKeyCredentialCreationOptions}
		 * @return the new {@link PublicKeyCredentialCreationOptions}
		 */
		public PublicKeyCredentialCreationOptions build() {
			return new PublicKeyCredentialCreationOptions(this.rp, this.user, this.challenge, this.pubKeyCredParams,
					this.timeout, this.excludeCredentials, this.authenticatorSelection, this.attestation,
					this.extensions);
		}

	}

}
