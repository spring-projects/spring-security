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
import java.io.Serializable;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * A representation of an OpenID Client Registration Request and Response, which is sent
 * to and returned from the Client Registration Endpoint, and contains a set of claims
 * about the Client's Registration information. The claims are defined by the OpenID
 * Connect Dynamic Client Registration 1.0 specification.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @since 0.1.1
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
public final class OidcClientRegistration implements OidcClientMetadataClaimAccessor, Serializable {

	@Serial
	private static final long serialVersionUID = 6518710174552040014L;

	private final Map<String, Object> claims;

	private OidcClientRegistration(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	/**
	 * Returns the metadata as claims.
	 * @return a {@code Map} of the metadata as claims
	 */
	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
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
	public static final class Builder {

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder() {
		}

		/**
		 * Sets the Client Identifier, REQUIRED.
		 * @param clientId the Client Identifier
		 * @return the {@link Builder} for further configuration
		 */
		public Builder clientId(String clientId) {
			return claim(OidcClientMetadataClaimNames.CLIENT_ID, clientId);
		}

		/**
		 * Sets the time at which the Client Identifier was issued, OPTIONAL.
		 * @param clientIdIssuedAt the time at which the Client Identifier was issued
		 * @return the {@link Builder} for further configuration
		 */
		public Builder clientIdIssuedAt(Instant clientIdIssuedAt) {
			return claim(OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, clientIdIssuedAt);
		}

		/**
		 * Sets the Client Secret, OPTIONAL.
		 * @param clientSecret the Client Secret
		 * @return the {@link Builder} for further configuration
		 */
		public Builder clientSecret(String clientSecret) {
			return claim(OidcClientMetadataClaimNames.CLIENT_SECRET, clientSecret);
		}

		/**
		 * Sets the time at which the {@code client_secret} will expire or {@code null} if
		 * it will not expire, REQUIRED if {@code client_secret} was issued.
		 * @param clientSecretExpiresAt the time at which the {@code client_secret} will
		 * expire or {@code null} if it will not expire
		 * @return the {@link Builder} for further configuration
		 */
		public Builder clientSecretExpiresAt(Instant clientSecretExpiresAt) {
			return claim(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT, clientSecretExpiresAt);
		}

		/**
		 * Sets the name of the Client to be presented to the End-User, OPTIONAL.
		 * @param clientName the name of the Client to be presented to the End-User
		 * @return the {@link Builder} for further configuration
		 */
		public Builder clientName(String clientName) {
			return claim(OidcClientMetadataClaimNames.CLIENT_NAME, clientName);
		}

		/**
		 * Add the redirection {@code URI} used by the Client, REQUIRED.
		 * @param redirectUri the redirection {@code URI} used by the Client
		 * @return the {@link Builder} for further configuration
		 */
		public Builder redirectUri(String redirectUri) {
			addClaimToClaimList(OidcClientMetadataClaimNames.REDIRECT_URIS, redirectUri);
			return this;
		}

		/**
		 * A {@code Consumer} of the redirection {@code URI} values used by the Client,
		 * allowing the ability to add, replace, or remove, REQUIRED.
		 * @param redirectUrisConsumer a {@code Consumer} of the redirection {@code URI}
		 * values used by the Client
		 * @return the {@link Builder} for further configuration
		 */
		public Builder redirectUris(Consumer<List<String>> redirectUrisConsumer) {
			acceptClaimValues(OidcClientMetadataClaimNames.REDIRECT_URIS, redirectUrisConsumer);
			return this;
		}

		/**
		 * Add the post logout redirection {@code URI} used by the Client, OPTIONAL. The
		 * {@code post_logout_redirect_uri} parameter is used by the client when
		 * requesting that the End-User's User Agent be redirected to after a logout has
		 * been performed.
		 * @param postLogoutRedirectUri the post logout redirection {@code URI} used by
		 * the Client
		 * @return the {@link Builder} for further configuration
		 * @since 1.1
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
		 * @since 1.1
		 */
		public Builder postLogoutRedirectUris(Consumer<List<String>> postLogoutRedirectUrisConsumer) {
			acceptClaimValues(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS, postLogoutRedirectUrisConsumer);
			return this;
		}

		/**
		 * Sets the authentication method used by the Client for the Token Endpoint,
		 * OPTIONAL.
		 * @param tokenEndpointAuthenticationMethod the authentication method used by the
		 * Client for the Token Endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenEndpointAuthenticationMethod(String tokenEndpointAuthenticationMethod) {
			return claim(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD, tokenEndpointAuthenticationMethod);
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
		 * @since 0.2.2
		 */
		public Builder tokenEndpointAuthenticationSigningAlgorithm(String authenticationSigningAlgorithm) {
			return claim(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_SIGNING_ALG, authenticationSigningAlgorithm);
		}

		/**
		 * Add the OAuth 2.0 {@code grant_type} that the Client will restrict itself to
		 * using, OPTIONAL.
		 * @param grantType the OAuth 2.0 {@code grant_type} that the Client will restrict
		 * itself to using
		 * @return the {@link Builder} for further configuration
		 */
		public Builder grantType(String grantType) {
			addClaimToClaimList(OidcClientMetadataClaimNames.GRANT_TYPES, grantType);
			return this;
		}

		/**
		 * A {@code Consumer} of the OAuth 2.0 {@code grant_type} values that the Client
		 * will restrict itself to using, allowing the ability to add, replace, or remove,
		 * OPTIONAL.
		 * @param grantTypesConsumer a {@code Consumer} of the OAuth 2.0
		 * {@code grant_type} values that the Client will restrict itself to using
		 * @return the {@link Builder} for further configuration
		 */
		public Builder grantTypes(Consumer<List<String>> grantTypesConsumer) {
			acceptClaimValues(OidcClientMetadataClaimNames.GRANT_TYPES, grantTypesConsumer);
			return this;
		}

		/**
		 * Add the OAuth 2.0 {@code response_type} that the Client will restrict itself to
		 * using, OPTIONAL.
		 * @param responseType the OAuth 2.0 {@code response_type} that the Client will
		 * restrict itself to using
		 * @return the {@link Builder} for further configuration
		 */
		public Builder responseType(String responseType) {
			addClaimToClaimList(OidcClientMetadataClaimNames.RESPONSE_TYPES, responseType);
			return this;
		}

		/**
		 * A {@code Consumer} of the OAuth 2.0 {@code response_type} values that the
		 * Client will restrict itself to using, allowing the ability to add, replace, or
		 * remove, OPTIONAL.
		 * @param responseTypesConsumer a {@code Consumer} of the OAuth 2.0
		 * {@code response_type} values that the Client will restrict itself to using
		 * @return the {@link Builder} for further configuration
		 */
		public Builder responseTypes(Consumer<List<String>> responseTypesConsumer) {
			acceptClaimValues(OidcClientMetadataClaimNames.RESPONSE_TYPES, responseTypesConsumer);
			return this;
		}

		/**
		 * Add the OAuth 2.0 {@code scope} that the Client will restrict itself to using,
		 * OPTIONAL.
		 * @param scope the OAuth 2.0 {@code scope} that the Client will restrict itself
		 * to using
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scope(String scope) {
			addClaimToClaimList(OidcClientMetadataClaimNames.SCOPE, scope);
			return this;
		}

		/**
		 * A {@code Consumer} of the OAuth 2.0 {@code scope} values that the Client will
		 * restrict itself to using, allowing the ability to add, replace, or remove,
		 * OPTIONAL.
		 * @param scopesConsumer a {@code Consumer} of the OAuth 2.0 {@code scope} values
		 * that the Client will restrict itself to using
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scopes(Consumer<List<String>> scopesConsumer) {
			acceptClaimValues(OidcClientMetadataClaimNames.SCOPE, scopesConsumer);
			return this;
		}

		/**
		 * Sets the {@code URL} for the Client's JSON Web Key Set, OPTIONAL.
		 * @param jwkSetUrl the {@code URL} for the Client's JSON Web Key Set
		 * @return the {@link Builder} for further configuration
		 * @since 0.2.2
		 */
		public Builder jwkSetUrl(String jwkSetUrl) {
			return claim(OidcClientMetadataClaimNames.JWKS_URI, jwkSetUrl);
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
		 * @since 0.2.1
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
		 * @since 0.2.1
		 */
		public Builder registrationClientUrl(String registrationClientUrl) {
			return claim(OidcClientMetadataClaimNames.REGISTRATION_CLIENT_URI, registrationClientUrl);
		}

		/**
		 * Sets the claim.
		 * @param name the claim name
		 * @param value the claim value
		 * @return the {@link Builder} for further configuration
		 */
		public Builder claim(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.put(name, value);
			return this;
		}

		/**
		 * Provides access to every {@link #claim(String, Object)} declared so far
		 * allowing the ability to add, replace, or remove.
		 * @param claimsConsumer a {@code Consumer} of the claims
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		/**
		 * Validate the claims and build the {@link OidcClientRegistration}.
		 * <p>
		 * The following claims are REQUIRED: {@code client_id}, {@code redirect_uris}.
		 * @return the {@link OidcClientRegistration}
		 */
		public OidcClientRegistration build() {
			validate();
			return new OidcClientRegistration(this.claims);
		}

		private void validate() {
			if (this.claims.get(OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT) != null
					|| this.claims.get(OidcClientMetadataClaimNames.CLIENT_SECRET) != null) {
				Assert.notNull(this.claims.get(OidcClientMetadataClaimNames.CLIENT_ID), "client_id cannot be null");
			}
			if (this.claims.get(OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT) != null) {
				Assert.isInstanceOf(Instant.class, this.claims.get(OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT),
						"client_id_issued_at must be of type Instant");
			}
			if (this.claims.get(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT) != null) {
				Assert.notNull(this.claims.get(OidcClientMetadataClaimNames.CLIENT_SECRET),
						"client_secret cannot be null");
				Assert.isInstanceOf(Instant.class,
						this.claims.get(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT),
						"client_secret_expires_at must be of type Instant");
			}
			Assert.notNull(this.claims.get(OidcClientMetadataClaimNames.REDIRECT_URIS), "redirect_uris cannot be null");
			Assert.isInstanceOf(List.class, this.claims.get(OidcClientMetadataClaimNames.REDIRECT_URIS),
					"redirect_uris must be of type List");
			Assert.notEmpty((List<?>) this.claims.get(OidcClientMetadataClaimNames.REDIRECT_URIS),
					"redirect_uris cannot be empty");
			if (this.claims.get(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS) != null) {
				Assert.isInstanceOf(List.class, this.claims.get(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS),
						"post_logout_redirect_uris must be of type List");
				Assert.notEmpty((List<?>) this.claims.get(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS),
						"post_logout_redirect_uris cannot be empty");
			}
			if (this.claims.get(OidcClientMetadataClaimNames.GRANT_TYPES) != null) {
				Assert.isInstanceOf(List.class, this.claims.get(OidcClientMetadataClaimNames.GRANT_TYPES),
						"grant_types must be of type List");
				Assert.notEmpty((List<?>) this.claims.get(OidcClientMetadataClaimNames.GRANT_TYPES),
						"grant_types cannot be empty");
			}
			if (this.claims.get(OidcClientMetadataClaimNames.RESPONSE_TYPES) != null) {
				Assert.isInstanceOf(List.class, this.claims.get(OidcClientMetadataClaimNames.RESPONSE_TYPES),
						"response_types must be of type List");
				Assert.notEmpty((List<?>) this.claims.get(OidcClientMetadataClaimNames.RESPONSE_TYPES),
						"response_types cannot be empty");
			}
			if (this.claims.get(OidcClientMetadataClaimNames.SCOPE) != null) {
				Assert.isInstanceOf(List.class, this.claims.get(OidcClientMetadataClaimNames.SCOPE),
						"scope must be of type List");
				Assert.notEmpty((List<?>) this.claims.get(OidcClientMetadataClaimNames.SCOPE), "scope cannot be empty");
			}
			if (this.claims.get(OidcClientMetadataClaimNames.JWKS_URI) != null) {
				validateURL(this.claims.get(OidcClientMetadataClaimNames.JWKS_URI), "jwksUri must be a valid URL");
			}
		}

		@SuppressWarnings("unchecked")
		private void addClaimToClaimList(String name, String value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.computeIfAbsent(name, (k) -> new LinkedList<String>());
			((List<String>) this.claims.get(name)).add(value);
		}

		@SuppressWarnings("unchecked")
		private void acceptClaimValues(String name, Consumer<List<String>> valuesConsumer) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(valuesConsumer, "valuesConsumer cannot be null");
			this.claims.computeIfAbsent(name, (k) -> new LinkedList<String>());
			List<String> values = (List<String>) this.claims.get(name);
			valuesConsumer.accept(values);
		}

		private static void validateURL(Object url, String errorMessage) {
			if (URL.class.isAssignableFrom(url.getClass())) {
				return;
			}

			try {
				new URI(url.toString()).toURL();
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(errorMessage, ex);
			}
		}

	}

}
