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

package org.springframework.security.oauth2.server.resource;

import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.util.Assert;

/**
 * A representation of an OAuth 2.0 Protected Resource Metadata response, which is
 * returned from an OAuth 2.0 Resource Server's Metadata Endpoint, and contains a set of
 * claims about the Resource Server's configuration. The claims are defined by the OAuth
 * 2.0 Protected Resource Metadata specification (RFC 9728).
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2ProtectedResourceMetadataClaimAccessor
 * @see <a target="_blank" href="https://www.rfc-editor.org/rfc/rfc9728.html#section-2">2.
 * Protected Resource Metadata</a>
 */
public final class OAuth2ProtectedResourceMetadata
		implements OAuth2ProtectedResourceMetadataClaimAccessor, Serializable {

	@Serial
	private static final long serialVersionUID = -18589911827039000L;

	private final Map<String, Object> claims;

	private OAuth2ProtectedResourceMetadata(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	/**
	 * Returns the metadata as claims.
	 * @return a {@code Map} of the metadata as claims
	 */
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
	 * Helps configure an {@link OAuth2ProtectedResourceMetadata}.
	 */
	public static final class Builder {

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder() {
		}

		/**
		 * Sets the resource identifier for the protected resource, REQUIRED.
		 * @param resource the resource identifier {@code URL} for the protected resource
		 * @return the {@link Builder} for further configuration
		 */
		public Builder resource(String resource) {
			return claim(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE, resource);
		}

		/**
		 * Add the issuer identifier for an authorization server, OPTIONAL.
		 * @param authorizationServer the issuer identifier {@code URL} for an
		 * authorization server
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorizationServer(String authorizationServer) {
			addClaimToClaimList(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS, authorizationServer);
			return this;
		}

		/**
		 * A {@code Consumer} of the issuer identifier values for the authorization
		 * servers, allowing the ability to add, replace, or remove, OPTIONAL.
		 * @param authorizationServersConsumer a {@code Consumer} of the issuer identifier
		 * values for the authorization servers
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorizationServers(Consumer<List<String>> authorizationServersConsumer) {
			acceptClaimValues(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS,
					authorizationServersConsumer);
			return this;
		}

		/**
		 * Add a {@code scope} supported in authorization requests to the protected
		 * resource, RECOMMENDED.
		 * @param scope a {@code scope} supported in authorization requests to the
		 * protected resource
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scope(String scope) {
			addClaimToClaimList(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED, scope);
			return this;
		}

		/**
		 * A {@code Consumer} of the {@code scope} values supported in authorization
		 * requests to the protected resource, allowing the ability to add, replace, or
		 * remove, RECOMMENDED.
		 * @param scopesConsumer a {@code Consumer} of the {@code scope} values supported
		 * in authorization requests to the protected resource
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scopes(Consumer<List<String>> scopesConsumer) {
			acceptClaimValues(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED, scopesConsumer);
			return this;
		}

		/**
		 * Add a supported method for sending an OAuth 2.0 bearer token to the protected
		 * resource, OPTIONAL. Defined values are "header", "body" and "query".
		 * @param bearerMethod a supported method for sending an OAuth 2.0 bearer token to
		 * the protected resource
		 * @return the {@link Builder} for further configuration
		 */
		public Builder bearerMethod(String bearerMethod) {
			addClaimToClaimList(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED, bearerMethod);
			return this;
		}

		/**
		 * A {@code Consumer} of the supported methods for sending an OAuth 2.0 bearer
		 * token to the protected resource, allowing the ability to add, replace, or
		 * remove, OPTIONAL.
		 * @param bearerMethodsConsumer a {@code Consumer} of the supported methods for
		 * sending an OAuth 2.0 bearer token to the protected resource
		 * @return the {@link Builder} for further configuration
		 */
		public Builder bearerMethods(Consumer<List<String>> bearerMethodsConsumer) {
			acceptClaimValues(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED,
					bearerMethodsConsumer);
			return this;
		}

		/**
		 * Sets the name of the protected resource intended for display to the end user,
		 * RECOMMENDED.
		 * @param resourceName the name of the protected resource intended for display to
		 * the end user
		 * @return the {@link Builder} for further configuration
		 */
		public Builder resourceName(String resourceName) {
			return claim(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE_NAME, resourceName);
		}

		/**
		 * Set to {@code true} to indicate protected resource support for mutual-TLS
		 * client certificate-bound access tokens, OPTIONAL.
		 * @param tlsClientCertificateBoundAccessTokens {@code true} to indicate protected
		 * resource support for mutual-TLS client certificate-bound access tokens
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tlsClientCertificateBoundAccessTokens(boolean tlsClientCertificateBoundAccessTokens) {
			return claim(OAuth2ProtectedResourceMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS,
					tlsClientCertificateBoundAccessTokens);
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
		 * Validate the claims and build the {@link OAuth2ProtectedResourceMetadata}.
		 * @return the {@link OAuth2ProtectedResourceMetadata}
		 */
		public OAuth2ProtectedResourceMetadata build() {
			validate();
			return new OAuth2ProtectedResourceMetadata(this.claims);
		}

		private void validate() {
			Assert.notNull(this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE),
					"resource cannot be null");
			validateURL(this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE),
					"resource must be a valid URL");
			if (this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS) != null) {
				Assert.isInstanceOf(List.class,
						this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS),
						"authorization_servers must be of type List");
				Assert.notEmpty(
						(List<?>) this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS),
						"authorization_servers cannot be empty");
				List<?> authorizationServers = (List<?>) this.claims
					.get(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS);
				authorizationServers.forEach((authorizationServer) -> validateURL(authorizationServer,
						"authorization_server must be a valid URL"));
			}
			if (this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED) != null) {
				Assert.isInstanceOf(List.class,
						this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED),
						"scopes must be of type List");
				Assert.notEmpty((List<?>) this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED),
						"scopes cannot be empty");
			}
			if (this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED) != null) {
				Assert.isInstanceOf(List.class,
						this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED),
						"bearer methods must be of type List");
				Assert.notEmpty(
						(List<?>) this.claims.get(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED),
						"bearer methods cannot be empty");
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
