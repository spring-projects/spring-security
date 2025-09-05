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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.util.Assert;

/**
 * A base representation of OAuth 2.0 Authorization Server metadata, returned by an
 * endpoint defined in OAuth 2.0 Authorization Server Metadata and OpenID Connect
 * Discovery 1.0. The metadata endpoint returns a set of claims an Authorization Server
 * describes about its configuration.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 * @since 0.1.1
 * @see OAuth2AuthorizationServerMetadataClaimAccessor
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8414#section-3.2">3.2.
 * Authorization Server Metadata Response</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">4.2.
 * OpenID Provider Configuration Response</a>
 * @see <a target="_blank" href="https://www.rfc-editor.org/rfc/rfc8628.html#section-4">4.
 * Device Authorization Grant Metadata</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc8705#section-3.3">3.3 Mutual-TLS Client
 * Certificate-Bound Access Tokens Metadata</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc9449#section-5.1">5.1 OAuth 2.0 Demonstrating
 * Proof of Possession (DPoP) Metadata</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc9126#name-authorization-server-metada">5.
 * OAuth 2.0 Pushed Authorization Requests Metadata</a>
 */
public abstract class AbstractOAuth2AuthorizationServerMetadata
		implements OAuth2AuthorizationServerMetadataClaimAccessor, Serializable {

	@Serial
	private static final long serialVersionUID = -8817963285912690443L;

	private final Map<String, Object> claims;

	protected AbstractOAuth2AuthorizationServerMetadata(Map<String, Object> claims) {
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
	 * A builder for subclasses of {@link AbstractOAuth2AuthorizationServerMetadata}.
	 *
	 * @param <T> the type of object
	 * @param <B> the type of the builder
	 */
	protected abstract static class AbstractBuilder<T extends AbstractOAuth2AuthorizationServerMetadata, B extends AbstractBuilder<T, B>> {

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
		 * Use this {@code issuer} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, REQUIRED.
		 * @param issuer the {@code URL} of the Authorization Server's Issuer Identifier
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B issuer(String issuer) {
			return claim(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, issuer);
		}

		/**
		 * Use this {@code authorization_endpoint} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, REQUIRED.
		 * @param authorizationEndpoint the {@code URL} of the OAuth 2.0 Authorization
		 * Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B authorizationEndpoint(String authorizationEndpoint) {
			return claim(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT, authorizationEndpoint);
		}

		/**
		 * Use this {@code pushed_authorization_request_endpoint} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param pushedAuthorizationRequestEndpoint the {@code URL} of the OAuth 2.0
		 * Pushed Authorization Request Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 * @since 1.5
		 */
		public B pushedAuthorizationRequestEndpoint(String pushedAuthorizationRequestEndpoint) {
			return claim(OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT,
					pushedAuthorizationRequestEndpoint);
		}

		/**
		 * Use this {@code device_authorization_endpoint} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param deviceAuthorizationEndpoint the {@code URL} of the OAuth 2.0 Device
		 * Authorization Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 * @since 1.1
		 */
		public B deviceAuthorizationEndpoint(String deviceAuthorizationEndpoint) {
			return claim(OAuth2AuthorizationServerMetadataClaimNames.DEVICE_AUTHORIZATION_ENDPOINT,
					deviceAuthorizationEndpoint);
		}

		/**
		 * Use this {@code token_endpoint} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, REQUIRED.
		 * @param tokenEndpoint the {@code URL} of the OAuth 2.0 Token Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenEndpoint(String tokenEndpoint) {
			return claim(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, tokenEndpoint);
		}

		/**
		 * Add this client authentication method to the collection of
		 * {@code token_endpoint_auth_methods_supported} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param authenticationMethod the client authentication method supported by the
		 * OAuth 2.0 Token Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenEndpointAuthenticationMethod(String authenticationMethod) {
			addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
					authenticationMethod);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the client authentication method(s) allowing the ability
		 * to add, replace, or remove.
		 * @param authenticationMethodsConsumer a {@code Consumer} of the client
		 * authentication method(s) supported by the OAuth 2.0 Token Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenEndpointAuthenticationMethods(Consumer<List<String>> authenticationMethodsConsumer) {
			acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
					authenticationMethodsConsumer);
			return getThis();
		}

		/**
		 * Use this {@code jwks_uri} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param jwkSetUrl the {@code URL} of the JSON Web Key Set
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B jwkSetUrl(String jwkSetUrl) {
			return claim(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, jwkSetUrl);
		}

		/**
		 * Add this OAuth 2.0 {@code scope} to the collection of {@code scopes_supported}
		 * in the resulting {@link AbstractOAuth2AuthorizationServerMetadata},
		 * RECOMMENDED.
		 * @param scope the OAuth 2.0 {@code scope} value supported
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B scope(String scope) {
			addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, scope);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the OAuth 2.0 {@code scope} values supported allowing the
		 * ability to add, replace, or remove.
		 * @param scopesConsumer a {@code Consumer} of the OAuth 2.0 {@code scope} values
		 * supported
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B scopes(Consumer<List<String>> scopesConsumer) {
			acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, scopesConsumer);
			return getThis();
		}

		/**
		 * Add this OAuth 2.0 {@code response_type} to the collection of
		 * {@code response_types_supported} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, REQUIRED.
		 * @param responseType the OAuth 2.0 {@code response_type} value supported
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B responseType(String responseType) {
			addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, responseType);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the OAuth 2.0 {@code response_type} values supported
		 * allowing the ability to add, replace, or remove.
		 * @param responseTypesConsumer a {@code Consumer} of the OAuth 2.0
		 * {@code response_type} values supported
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B responseTypes(Consumer<List<String>> responseTypesConsumer) {
			acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED,
					responseTypesConsumer);
			return getThis();
		}

		/**
		 * Add this OAuth 2.0 {@code grant_type} to the collection of
		 * {@code grant_types_supported} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param grantType the OAuth 2.0 {@code grant_type} value supported
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B grantType(String grantType) {
			addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, grantType);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the OAuth 2.0 {@code grant_type} values supported
		 * allowing the ability to add, replace, or remove.
		 * @param grantTypesConsumer a {@code Consumer} of the OAuth 2.0
		 * {@code grant_type} values supported
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B grantTypes(Consumer<List<String>> grantTypesConsumer) {
			acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, grantTypesConsumer);
			return getThis();
		}

		/**
		 * Use this {@code revocation_endpoint} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param tokenRevocationEndpoint the {@code URL} of the OAuth 2.0 Token
		 * Revocation Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenRevocationEndpoint(String tokenRevocationEndpoint) {
			return claim(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT, tokenRevocationEndpoint);
		}

		/**
		 * Add this client authentication method to the collection of
		 * {@code revocation_endpoint_auth_methods_supported} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param authenticationMethod the client authentication method supported by the
		 * OAuth 2.0 Token Revocation Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenRevocationEndpointAuthenticationMethod(String authenticationMethod) {
			addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED,
					authenticationMethod);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the client authentication method(s) allowing the ability
		 * to add, replace, or remove.
		 * @param authenticationMethodsConsumer a {@code Consumer} of the client
		 * authentication method(s) supported by the OAuth 2.0 Token Revocation Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenRevocationEndpointAuthenticationMethods(Consumer<List<String>> authenticationMethodsConsumer) {
			acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED,
					authenticationMethodsConsumer);
			return getThis();
		}

		/**
		 * Use this {@code introspection_endpoint} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param tokenIntrospectionEndpoint the {@code URL} of the OAuth 2.0 Token
		 * Introspection Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenIntrospectionEndpoint(String tokenIntrospectionEndpoint) {
			return claim(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT,
					tokenIntrospectionEndpoint);
		}

		/**
		 * Add this client authentication method to the collection of
		 * {@code introspection_endpoint_auth_methods_supported} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param authenticationMethod the client authentication method supported by the
		 * OAuth 2.0 Token Introspection Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenIntrospectionEndpointAuthenticationMethod(String authenticationMethod) {
			addClaimToClaimList(
					OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED,
					authenticationMethod);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the client authentication method(s) allowing the ability
		 * to add, replace, or remove.
		 * @param authenticationMethodsConsumer a {@code Consumer} of the client
		 * authentication method(s) supported by the OAuth 2.0 Token Introspection
		 * Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenIntrospectionEndpointAuthenticationMethods(Consumer<List<String>> authenticationMethodsConsumer) {
			acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED,
					authenticationMethodsConsumer);
			return getThis();
		}

		/**
		 * Use this {@code registration_endpoint} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param clientRegistrationEndpoint the {@code URL} of the OAuth 2.0 Dynamic
		 * Client Registration Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 * @since 0.4.0
		 */
		public B clientRegistrationEndpoint(String clientRegistrationEndpoint) {
			return claim(OAuth2AuthorizationServerMetadataClaimNames.REGISTRATION_ENDPOINT, clientRegistrationEndpoint);
		}

		/**
		 * Add this Proof Key for Code Exchange (PKCE) {@code code_challenge_method} to
		 * the collection of {@code code_challenge_methods_supported} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param codeChallengeMethod the {@code code_challenge_method} value supported
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B codeChallengeMethod(String codeChallengeMethod) {
			addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED,
					codeChallengeMethod);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the Proof Key for Code Exchange (PKCE)
		 * {@code code_challenge_method} values supported allowing the ability to add,
		 * replace, or remove.
		 * @param codeChallengeMethodsConsumer a {@code Consumer} of the
		 * {@code code_challenge_method} values supported
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B codeChallengeMethods(Consumer<List<String>> codeChallengeMethodsConsumer) {
			acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED,
					codeChallengeMethodsConsumer);
			return getThis();
		}

		/**
		 * Use this {@code tls_client_certificate_bound_access_tokens} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param tlsClientCertificateBoundAccessTokens {@code true} to indicate support
		 * for mutual-TLS client certificate-bound access tokens
		 * @return the {@link AbstractBuilder} for further configuration
		 * @since 1.3
		 */
		public B tlsClientCertificateBoundAccessTokens(boolean tlsClientCertificateBoundAccessTokens) {
			return claim(OAuth2AuthorizationServerMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS,
					tlsClientCertificateBoundAccessTokens);
		}

		/**
		 * Add a {@link JwsAlgorithms JSON Web Signature (JWS) algorithm} to the
		 * collection of {@code dpop_signing_alg_values_supported} in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}, OPTIONAL.
		 * @param dPoPSigningAlgorithm the {@link JwsAlgorithms JSON Web Signature (JWS)
		 * algorithm} supported for DPoP Proof JWTs
		 * @return the {@link AbstractBuilder} for further configuration
		 * @since 1.5
		 */
		public B dPoPSigningAlgorithm(String dPoPSigningAlgorithm) {
			addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED,
					dPoPSigningAlgorithm);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the {@link JwsAlgorithms JSON Web Signature (JWS)
		 * algorithms} supported for DPoP Proof JWTs allowing the ability to add, replace,
		 * or remove.
		 * @param dPoPSigningAlgorithmsConsumer a {@code Consumer} of the
		 * {@link JwsAlgorithms JSON Web Signature (JWS) algorithms} supported for DPoP
		 * Proof JWTs
		 * @return the {@link AbstractBuilder} for further configuration
		 * @since 1.5
		 */
		public B dPoPSigningAlgorithms(Consumer<List<String>> dPoPSigningAlgorithmsConsumer) {
			acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED,
					dPoPSigningAlgorithmsConsumer);
			return getThis();
		}

		/**
		 * Use this claim in the resulting
		 * {@link AbstractOAuth2AuthorizationServerMetadata}.
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
		 * Provides access to every {@link #claim(String, Object)} declared so far with
		 * the possibility to add, replace, or remove.
		 * @param claimsConsumer a {@code Consumer} of the claims
		 * @return the {@link AbstractBuilder} for further configurations
		 */
		public B claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return getThis();
		}

		/**
		 * Creates the {@link AbstractOAuth2AuthorizationServerMetadata}.
		 * @return the {@link AbstractOAuth2AuthorizationServerMetadata}
		 */
		public abstract T build();

		protected void validate() {
			Assert.notNull(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.ISSUER),
					"issuer cannot be null");
			validateURL(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.ISSUER),
					"issuer must be a valid URL");
			Assert.notNull(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT),
					"authorizationEndpoint cannot be null");
			validateURL(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT),
					"authorizationEndpoint must be a valid URL");
			if (getClaims()
				.get(OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT) != null) {
				validateURL(
						getClaims()
							.get(OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT),
						"pushedAuthorizationRequestEndpoint must be a valid URL");
			}
			if (getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.DEVICE_AUTHORIZATION_ENDPOINT) != null) {
				validateURL(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.DEVICE_AUTHORIZATION_ENDPOINT),
						"deviceAuthorizationEndpoint must be a valid URL");
			}
			Assert.notNull(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT),
					"tokenEndpoint cannot be null");
			validateURL(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT),
					"tokenEndpoint must be a valid URL");
			if (getClaims()
				.get(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED) != null) {
				Assert.isInstanceOf(List.class,
						getClaims()
							.get(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED),
						"tokenEndpointAuthenticationMethods must be of type List");
				Assert.notEmpty(
						(List<?>) getClaims()
							.get(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED),
						"tokenEndpointAuthenticationMethods cannot be empty");
			}
			if (getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI) != null) {
				validateURL(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI),
						"jwksUri must be a valid URL");
			}
			if (getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED) != null) {
				Assert.isInstanceOf(List.class,
						getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED),
						"scopes must be of type List");
				Assert.notEmpty((List<?>) getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED),
						"scopes cannot be empty");
			}
			Assert.notNull(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED),
					"responseTypes cannot be null");
			Assert.isInstanceOf(List.class,
					getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED),
					"responseTypes must be of type List");
			Assert.notEmpty(
					(List<?>) getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED),
					"responseTypes cannot be empty");
			if (getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED) != null) {
				Assert.isInstanceOf(List.class,
						getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED),
						"grantTypes must be of type List");
				Assert.notEmpty(
						(List<?>) getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED),
						"grantTypes cannot be empty");
			}
			if (getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT) != null) {
				validateURL(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT),
						"tokenRevocationEndpoint must be a valid URL");
			}
			if (getClaims()
				.get(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED) != null) {
				Assert.isInstanceOf(List.class,
						getClaims().get(
								OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED),
						"tokenRevocationEndpointAuthenticationMethods must be of type List");
				Assert.notEmpty(
						(List<?>) getClaims().get(
								OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED),
						"tokenRevocationEndpointAuthenticationMethods cannot be empty");
			}
			if (getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT) != null) {
				validateURL(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT),
						"tokenIntrospectionEndpoint must be a valid URL");
			}
			if (getClaims().get(
					OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED) != null) {
				Assert.isInstanceOf(List.class, getClaims()
					.get(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED),
						"tokenIntrospectionEndpointAuthenticationMethods must be of type List");
				Assert.notEmpty((List<?>) getClaims()
					.get(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED),
						"tokenIntrospectionEndpointAuthenticationMethods cannot be empty");
			}
			if (getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.REGISTRATION_ENDPOINT) != null) {
				validateURL(getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.REGISTRATION_ENDPOINT),
						"clientRegistrationEndpoint must be a valid URL");
			}
			if (getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED) != null) {
				Assert.isInstanceOf(List.class,
						getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED),
						"codeChallengeMethods must be of type List");
				Assert.notEmpty(
						(List<?>) getClaims()
							.get(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED),
						"codeChallengeMethods cannot be empty");
			}
			if (getClaims()
				.get(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED) != null) {
				Assert.isInstanceOf(List.class,
						getClaims().get(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED),
						"dPoPSigningAlgorithms must be of type List");
				Assert.notEmpty(
						(List<?>) getClaims()
							.get(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED),
						"dPoPSigningAlgorithms cannot be empty");
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

		protected static void validateURL(Object url, String errorMessage) {
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
