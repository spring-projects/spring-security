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

package org.springframework.security.oauth2.server.authorization.oidc;

import java.io.Serial;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.AbstractOAuth2ClientRegistration;
import org.springframework.util.Assert;

/**
 * A representation of an OpenID Client Registration Request and Response, which is sent
 * to and returned from the Client Registration Endpoint, and contains a set of claims
 * about the Client's Registration information. The claims are defined by the OpenID
 * Connect Dynamic Client Registration 1.0 specification.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @since 7.0
 * @see AbstractOAuth2ClientRegistration
 * @see OidcClientMetadataClaimAccessor
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationRequest">3.1.
 * Client Registration Request</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse">3.2.
 * Client Registration Response</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ClientMetadata">3.1.
 * Client Registration Metadata</a>
 */
public final class OidcClientRegistration extends AbstractOAuth2ClientRegistration
		implements OidcClientMetadataClaimAccessor {

	@Serial
	private static final long serialVersionUID = -8485448209864668396L;

	private OidcClientRegistration(Map<String, Object> claims) {
		super(claims);
	}

	/**
	 * Constructs a new {@link Builder} with empty claims.
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Constructs a new {@link Builder} with the provided claims.
	 * @param claims the claims to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder withClaims(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		return new Builder().claims((c) -> c.putAll(claims));
	}

	/**
	 * Helps configure an {@link OidcClientRegistration}.
	 */
	public static final class Builder extends AbstractBuilder<OidcClientRegistration, Builder> {

		private Builder() {
		}

		/**
		 * Add the post logout redirection {@code URI} used by the Client, OPTIONAL. The
		 * {@code post_logout_redirect_uri} parameter is used by the client when
		 * requesting that the End-User's User Agent be redirected to after a logout has
		 * been performed.
		 * @param postLogoutRedirectUri the post logout redirection {@code URI} used by
		 * the Client
		 * @return the {@link Builder} for further configuration
		 */
		public Builder postLogoutRedirectUri(String postLogoutRedirectUri) {
			addClaimToClaimList(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS, postLogoutRedirectUri);
			return this;
		}

		/**
		 * A {@code Consumer} of the post logout redirection {@code URI} values used by
		 * the Client, allowing the ability to add, replace, or remove, OPTIONAL.
		 * @param postLogoutRedirectUrisConsumer a {@code Consumer} of the post logout
		 * redirection {@code URI} values used by the Client
		 * @return the {@link Builder} for further configuration
		 */
		public Builder postLogoutRedirectUris(Consumer<List<String>> postLogoutRedirectUrisConsumer) {
			acceptClaimValues(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS, postLogoutRedirectUrisConsumer);
			return this;
		}

		/**
		 * Sets the {@link JwsAlgorithm JWS} algorithm that must be used for signing the
		 * {@link Jwt JWT} used to authenticate the Client at the Token Endpoint for the
		 * {@link ClientAuthenticationMethod#PRIVATE_KEY_JWT private_key_jwt} and
		 * {@link ClientAuthenticationMethod#CLIENT_SECRET_JWT client_secret_jwt}
		 * authentication methods, OPTIONAL.
		 * @param authenticationSigningAlgorithm the {@link JwsAlgorithm JWS} algorithm
		 * that must be used for signing the {@link Jwt JWT} used to authenticate the
		 * Client at the Token Endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenEndpointAuthenticationSigningAlgorithm(String authenticationSigningAlgorithm) {
			return claim(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_SIGNING_ALG, authenticationSigningAlgorithm);
		}

		/**
		 * Sets the {@link SignatureAlgorithm JWS} algorithm required for signing the
		 * {@link OidcIdToken ID Token} issued to the Client, OPTIONAL.
		 * @param idTokenSignedResponseAlgorithm the {@link SignatureAlgorithm JWS}
		 * algorithm required for signing the {@link OidcIdToken ID Token} issued to the
		 * Client
		 * @return the {@link Builder} for further configuration
		 */
		public Builder idTokenSignedResponseAlgorithm(String idTokenSignedResponseAlgorithm) {
			return claim(OidcClientMetadataClaimNames.ID_TOKEN_SIGNED_RESPONSE_ALG, idTokenSignedResponseAlgorithm);
		}

		/**
		 * Sets the Registration Access Token that can be used at the Client Configuration
		 * Endpoint, OPTIONAL.
		 * @param registrationAccessToken the Registration Access Token that can be used
		 * at the Client Configuration Endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder registrationAccessToken(String registrationAccessToken) {
			return claim(OidcClientMetadataClaimNames.REGISTRATION_ACCESS_TOKEN, registrationAccessToken);
		}

		/**
		 * Sets the {@code URL} of the Client Configuration Endpoint where the
		 * Registration Access Token can be used, OPTIONAL.
		 * @param registrationClientUrl the {@code URL} of the Client Configuration
		 * Endpoint where the Registration Access Token can be used
		 * @return the {@link Builder} for further configuration
		 */
		public Builder registrationClientUrl(String registrationClientUrl) {
			return claim(OidcClientMetadataClaimNames.REGISTRATION_CLIENT_URI, registrationClientUrl);
		}

		/**
		 * Validate the claims and build the {@link OidcClientRegistration}.
		 * <p>
		 * The following claims are REQUIRED: {@code client_id}, {@code redirect_uris}.
		 * @return the {@link OidcClientRegistration}
		 */
		@Override
		public OidcClientRegistration build() {
			validate();
			return new OidcClientRegistration(getClaims());
		}

		@Override
		protected void validate() {
			super.validate();
			Assert.notNull(getClaims().get(OidcClientMetadataClaimNames.REDIRECT_URIS), "redirect_uris cannot be null");
			Assert.isInstanceOf(List.class, getClaims().get(OidcClientMetadataClaimNames.REDIRECT_URIS),
					"redirect_uris must be of type List");
			Assert.notEmpty((List<?>) getClaims().get(OidcClientMetadataClaimNames.REDIRECT_URIS),
					"redirect_uris cannot be empty");
			if (getClaims().get(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS) != null) {
				Assert.isInstanceOf(List.class, getClaims().get(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS),
						"post_logout_redirect_uris must be of type List");
				Assert.notEmpty((List<?>) getClaims().get(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS),
						"post_logout_redirect_uris cannot be empty");
			}
		}

		@SuppressWarnings("unchecked")
		private void addClaimToClaimList(String name, String value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			getClaims().computeIfAbsent(name, (k) -> new LinkedList<String>());
			((List<String>) getClaims().get(name)).add(value);
		}

		@SuppressWarnings("unchecked")
		private void acceptClaimValues(String name, Consumer<List<String>> valuesConsumer) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(valuesConsumer, "valuesConsumer cannot be null");
			getClaims().computeIfAbsent(name, (k) -> new LinkedList<String>());
			List<String> values = (List<String>) getClaims().get(name);
			valuesConsumer.accept(values);
		}

	}

}
