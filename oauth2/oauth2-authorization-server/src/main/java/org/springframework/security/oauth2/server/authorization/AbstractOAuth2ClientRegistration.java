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

package org.springframework.security.oauth2.server.authorization;

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

import org.springframework.util.Assert;

/**
 * A base representation of an OAuth 2.0 Client Registration Request and Response, which
 * is sent to and returned from the Client Registration Endpoint, and contains a set of
 * claims about the Client's Registration information. The claims are defined by the OAuth
 * 2.0 Dynamic Client Registration Protocol specification.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2ClientMetadataClaimAccessor
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc7591#section-3.1">3.1. Client Registration
 * Request</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1">3.2.1. Client
 * Registration Response</a>
 */
public abstract class AbstractOAuth2ClientRegistration implements OAuth2ClientMetadataClaimAccessor, Serializable {

	@Serial
	private static final long serialVersionUID = 8042785346181558593L;

	private final Map<String, Object> claims;

	protected AbstractOAuth2ClientRegistration(Map<String, Object> claims) {
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
	 * A builder for subclasses of {@link AbstractOAuth2ClientRegistration}.
	 *
	 * @param <T> the type of object
	 * @param <B> the type of the builder
	 */
	protected abstract static class AbstractBuilder<T extends AbstractOAuth2ClientRegistration, B extends AbstractBuilder<T, B>> {

		private final Map<String, Object> claims = new LinkedHashMap<>();

		protected AbstractBuilder() {
		}

		protected Map<String, Object> getClaims() {
			return this.claims;
		}

		@SuppressWarnings("unchecked")
		protected final B getThis() {
			// avoid unchecked casts in subclasses by using "getThis()" instead of "(B)
			// this"
			return (B) this;
		}

		/**
		 * Sets the Client Identifier, REQUIRED.
		 * @param clientId the Client Identifier
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B clientId(String clientId) {
			return claim(OAuth2ClientMetadataClaimNames.CLIENT_ID, clientId);
		}

		/**
		 * Sets the time at which the Client Identifier was issued, OPTIONAL.
		 * @param clientIdIssuedAt the time at which the Client Identifier was issued
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B clientIdIssuedAt(Instant clientIdIssuedAt) {
			return claim(OAuth2ClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, clientIdIssuedAt);
		}

		/**
		 * Sets the Client Secret, OPTIONAL.
		 * @param clientSecret the Client Secret
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B clientSecret(String clientSecret) {
			return claim(OAuth2ClientMetadataClaimNames.CLIENT_SECRET, clientSecret);
		}

		/**
		 * Sets the time at which the {@code client_secret} will expire or {@code null} if
		 * it will not expire, REQUIRED if {@code client_secret} was issued.
		 * @param clientSecretExpiresAt the time at which the {@code client_secret} will
		 * expire or {@code null} if it will not expire
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B clientSecretExpiresAt(Instant clientSecretExpiresAt) {
			return claim(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT, clientSecretExpiresAt);
		}

		/**
		 * Sets the name of the Client to be presented to the End-User, OPTIONAL.
		 * @param clientName the name of the Client to be presented to the End-User
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B clientName(String clientName) {
			return claim(OAuth2ClientMetadataClaimNames.CLIENT_NAME, clientName);
		}

		/**
		 * Add the redirection {@code URI} used by the Client, REQUIRED for redirect-based
		 * flows.
		 * @param redirectUri the redirection {@code URI} used by the Client
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B redirectUri(String redirectUri) {
			addClaimToClaimList(OAuth2ClientMetadataClaimNames.REDIRECT_URIS, redirectUri);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the redirection {@code URI} values used by the Client,
		 * allowing the ability to add, replace, or remove, REQUIRED for redirect-based
		 * flows.
		 * @param redirectUrisConsumer a {@code Consumer} of the redirection {@code URI}
		 * values used by the Client
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B redirectUris(Consumer<List<String>> redirectUrisConsumer) {
			acceptClaimValues(OAuth2ClientMetadataClaimNames.REDIRECT_URIS, redirectUrisConsumer);
			return getThis();
		}

		/**
		 * Sets the authentication method used by the Client for the Token Endpoint,
		 * OPTIONAL.
		 * @param tokenEndpointAuthenticationMethod the authentication method used by the
		 * Client for the Token Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenEndpointAuthenticationMethod(String tokenEndpointAuthenticationMethod) {
			return claim(OAuth2ClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD, tokenEndpointAuthenticationMethod);
		}

		/**
		 * Add the OAuth 2.0 {@code grant_type} that the Client will restrict itself to
		 * using, OPTIONAL.
		 * @param grantType the OAuth 2.0 {@code grant_type} that the Client will restrict
		 * itself to using
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B grantType(String grantType) {
			addClaimToClaimList(OAuth2ClientMetadataClaimNames.GRANT_TYPES, grantType);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the OAuth 2.0 {@code grant_type} values that the Client
		 * will restrict itself to using, allowing the ability to add, replace, or remove,
		 * OPTIONAL.
		 * @param grantTypesConsumer a {@code Consumer} of the OAuth 2.0
		 * {@code grant_type} values that the Client will restrict itself to using
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B grantTypes(Consumer<List<String>> grantTypesConsumer) {
			acceptClaimValues(OAuth2ClientMetadataClaimNames.GRANT_TYPES, grantTypesConsumer);
			return getThis();
		}

		/**
		 * Add the OAuth 2.0 {@code response_type} that the Client will restrict itself to
		 * using, OPTIONAL.
		 * @param responseType the OAuth 2.0 {@code response_type} that the Client will
		 * restrict itself to using
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B responseType(String responseType) {
			addClaimToClaimList(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES, responseType);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the OAuth 2.0 {@code response_type} values that the
		 * Client will restrict itself to using, allowing the ability to add, replace, or
		 * remove, OPTIONAL.
		 * @param responseTypesConsumer a {@code Consumer} of the OAuth 2.0
		 * {@code response_type} values that the Client will restrict itself to using
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B responseTypes(Consumer<List<String>> responseTypesConsumer) {
			acceptClaimValues(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES, responseTypesConsumer);
			return getThis();
		}

		/**
		 * Add the OAuth 2.0 {@code scope} that the Client will restrict itself to using,
		 * OPTIONAL.
		 * @param scope the OAuth 2.0 {@code scope} that the Client will restrict itself
		 * to using
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B scope(String scope) {
			addClaimToClaimList(OAuth2ClientMetadataClaimNames.SCOPE, scope);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the OAuth 2.0 {@code scope} values that the Client will
		 * restrict itself to using, allowing the ability to add, replace, or remove,
		 * OPTIONAL.
		 * @param scopesConsumer a {@code Consumer} of the OAuth 2.0 {@code scope} values
		 * that the Client will restrict itself to using
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B scopes(Consumer<List<String>> scopesConsumer) {
			acceptClaimValues(OAuth2ClientMetadataClaimNames.SCOPE, scopesConsumer);
			return getThis();
		}

		/**
		 * Sets the {@code URL} for the Client's JSON Web Key Set, OPTIONAL.
		 * @param jwkSetUrl the {@code URL} for the Client's JSON Web Key Set
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B jwkSetUrl(String jwkSetUrl) {
			return claim(OAuth2ClientMetadataClaimNames.JWKS_URI, jwkSetUrl);
		}

		/**
		 * Sets the claim.
		 * @param name the claim name
		 * @param value the claim value
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B claim(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.put(name, value);
			return getThis();
		}

		/**
		 * Provides access to every {@link #claim(String, Object)} declared so far
		 * allowing the ability to add, replace, or remove.
		 * @param claimsConsumer a {@code Consumer} of the claims
		 * @return the {@link AbstractBuilder} for further configurations
		 */
		public B claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return getThis();
		}

		/**
		 * Validate the claims and build the {@link AbstractOAuth2ClientRegistration}.
		 * @return the {@link AbstractOAuth2ClientRegistration}
		 */
		public abstract T build();

		protected void validate() {
			if (this.claims.get(OAuth2ClientMetadataClaimNames.CLIENT_ID_ISSUED_AT) != null
					|| this.claims.get(OAuth2ClientMetadataClaimNames.CLIENT_SECRET) != null) {
				Assert.notNull(this.claims.get(OAuth2ClientMetadataClaimNames.CLIENT_ID), "client_id cannot be null");
			}
			if (this.claims.get(OAuth2ClientMetadataClaimNames.CLIENT_ID_ISSUED_AT) != null) {
				Assert.isInstanceOf(Instant.class, this.claims.get(OAuth2ClientMetadataClaimNames.CLIENT_ID_ISSUED_AT),
						"client_id_issued_at must be of type Instant");
			}
			if (this.claims.get(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT) != null) {
				Assert.notNull(this.claims.get(OAuth2ClientMetadataClaimNames.CLIENT_SECRET),
						"client_secret cannot be null");
				Assert.isInstanceOf(Instant.class,
						this.claims.get(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT),
						"client_secret_expires_at must be of type Instant");
			}
			if (this.claims.get(OAuth2ClientMetadataClaimNames.REDIRECT_URIS) != null) {
				Assert.isInstanceOf(List.class, this.claims.get(OAuth2ClientMetadataClaimNames.REDIRECT_URIS),
						"redirect_uris must be of type List");
				Assert.notEmpty((List<?>) this.claims.get(OAuth2ClientMetadataClaimNames.REDIRECT_URIS),
						"redirect_uris cannot be empty");
			}
			if (this.claims.get(OAuth2ClientMetadataClaimNames.GRANT_TYPES) != null) {
				Assert.isInstanceOf(List.class, this.claims.get(OAuth2ClientMetadataClaimNames.GRANT_TYPES),
						"grant_types must be of type List");
				Assert.notEmpty((List<?>) this.claims.get(OAuth2ClientMetadataClaimNames.GRANT_TYPES),
						"grant_types cannot be empty");
			}
			if (this.claims.get(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES) != null) {
				Assert.isInstanceOf(List.class, this.claims.get(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES),
						"response_types must be of type List");
				Assert.notEmpty((List<?>) this.claims.get(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES),
						"response_types cannot be empty");
			}
			if (this.claims.get(OAuth2ClientMetadataClaimNames.SCOPE) != null) {
				Assert.isInstanceOf(List.class, this.claims.get(OAuth2ClientMetadataClaimNames.SCOPE),
						"scope must be of type List");
				Assert.notEmpty((List<?>) this.claims.get(OAuth2ClientMetadataClaimNames.SCOPE),
						"scope cannot be empty");
			}
			if (this.claims.get(OAuth2ClientMetadataClaimNames.JWKS_URI) != null) {
				validateURL(this.claims.get(OAuth2ClientMetadataClaimNames.JWKS_URI), "jwksUri must be a valid URL");
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
