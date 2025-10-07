/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.settings;

import java.io.Serial;
import java.util.Map;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * A facility for client configuration settings.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see AbstractSettings
 * @see ConfigurationSettingNames.Client
 */
public final class ClientSettings extends AbstractSettings {

	@Serial
	private static final long serialVersionUID = 9015034829752473931L;

	private ClientSettings(Map<String, Object> settings) {
		super(settings);
	}

	/**
	 * Returns {@code true} if the client is required to provide a proof key challenge and
	 * verifier when performing the Authorization Code Grant flow. The default is
	 * {@code false}.
	 * @return {@code true} if the client is required to provide a proof key challenge and
	 * verifier, {@code false} otherwise
	 */
	public boolean isRequireProofKey() {
		return getSetting(ConfigurationSettingNames.Client.REQUIRE_PROOF_KEY);
	}

	/**
	 * Returns {@code true} if authorization consent is required when the client requests
	 * access. The default is {@code false}.
	 * @return {@code true} if authorization consent is required when the client requests
	 * access, {@code false} otherwise
	 */
	public boolean isRequireAuthorizationConsent() {
		return getSetting(ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT);
	}

	/**
	 * Returns the {@code URL} for the Client's JSON Web Key Set.
	 * @return the {@code URL} for the Client's JSON Web Key Set
	 */
	public String getJwkSetUrl() {
		return getSetting(ConfigurationSettingNames.Client.JWK_SET_URL);
	}

	/**
	 * Returns the {@link JwsAlgorithm JWS} algorithm that must be used for signing the
	 * {@link Jwt JWT} used to authenticate the Client at the Token Endpoint for the
	 * {@link ClientAuthenticationMethod#PRIVATE_KEY_JWT private_key_jwt} and
	 * {@link ClientAuthenticationMethod#CLIENT_SECRET_JWT client_secret_jwt}
	 * authentication methods.
	 * @return the {@link JwsAlgorithm JWS} algorithm that must be used for signing the
	 * {@link Jwt JWT} used to authenticate the Client at the Token Endpoint
	 */
	public JwsAlgorithm getTokenEndpointAuthenticationSigningAlgorithm() {
		return getSetting(ConfigurationSettingNames.Client.TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM);
	}

	/**
	 * Returns the expected subject distinguished name associated to the client
	 * {@code X509Certificate} received during client authentication when using the
	 * {@code tls_client_auth} method.
	 * @return the expected subject distinguished name associated to the client
	 * {@code X509Certificate} received during client authentication
	 */
	public String getX509CertificateSubjectDN() {
		return getSetting(ConfigurationSettingNames.Client.X509_CERTIFICATE_SUBJECT_DN);
	}

	/**
	 * Constructs a new {@link Builder} with the default settings.
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder().requireProofKey(false).requireAuthorizationConsent(false);
	}

	/**
	 * Constructs a new {@link Builder} with the provided settings.
	 * @param settings the settings to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder withSettings(Map<String, Object> settings) {
		Assert.notEmpty(settings, "settings cannot be empty");
		return new Builder().settings((s) -> s.putAll(settings));
	}

	/**
	 * A builder for {@link ClientSettings}.
	 */
	public static final class Builder extends AbstractBuilder<ClientSettings, Builder> {

		private Builder() {
		}

		/**
		 * Set to {@code true} if the client is required to provide a proof key challenge
		 * and verifier when performing the Authorization Code Grant flow.
		 * @param requireProofKey {@code true} if the client is required to provide a
		 * proof key challenge and verifier, {@code false} otherwise
		 * @return the {@link Builder} for further configuration
		 */
		public Builder requireProofKey(boolean requireProofKey) {
			return setting(ConfigurationSettingNames.Client.REQUIRE_PROOF_KEY, requireProofKey);
		}

		/**
		 * Set to {@code true} if authorization consent is required when the client
		 * requests access. This applies to {@code authorization_code} flow.
		 * @param requireAuthorizationConsent {@code true} if authorization consent is
		 * required when the client requests access, {@code false} otherwise
		 * @return the {@link Builder} for further configuration
		 */
		public Builder requireAuthorizationConsent(boolean requireAuthorizationConsent) {
			return setting(ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT, requireAuthorizationConsent);
		}

		/**
		 * Sets the {@code URL} for the Client's JSON Web Key Set.
		 * @param jwkSetUrl the {@code URL} for the Client's JSON Web Key Set
		 * @return the {@link Builder} for further configuration
		 */
		public Builder jwkSetUrl(String jwkSetUrl) {
			return setting(ConfigurationSettingNames.Client.JWK_SET_URL, jwkSetUrl);
		}

		/**
		 * Sets the {@link JwsAlgorithm JWS} algorithm that must be used for signing the
		 * {@link Jwt JWT} used to authenticate the Client at the Token Endpoint for the
		 * {@link ClientAuthenticationMethod#PRIVATE_KEY_JWT private_key_jwt} and
		 * {@link ClientAuthenticationMethod#CLIENT_SECRET_JWT client_secret_jwt}
		 * authentication methods.
		 * @param authenticationSigningAlgorithm the {@link JwsAlgorithm JWS} algorithm
		 * that must be used for signing the {@link Jwt JWT} used to authenticate the
		 * Client at the Token Endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenEndpointAuthenticationSigningAlgorithm(JwsAlgorithm authenticationSigningAlgorithm) {
			return setting(ConfigurationSettingNames.Client.TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM,
					authenticationSigningAlgorithm);
		}

		/**
		 * Sets the expected subject distinguished name associated to the client
		 * {@code X509Certificate} received during client authentication when using the
		 * {@code tls_client_auth} method.
		 * @param x509CertificateSubjectDN the expected subject distinguished name
		 * associated to the client {@code X509Certificate} received during client
		 * authentication * @return the {@link Builder} for further configuration
		 * @return the {@link Builder} for further configuration
		 */
		public Builder x509CertificateSubjectDN(String x509CertificateSubjectDN) {
			return setting(ConfigurationSettingNames.Client.X509_CERTIFICATE_SUBJECT_DN, x509CertificateSubjectDN);
		}

		/**
		 * Builds the {@link ClientSettings}.
		 * @return the {@link ClientSettings}
		 */
		@Override
		public ClientSettings build() {
			return new ClientSettings(getSettings());
		}

	}

}
