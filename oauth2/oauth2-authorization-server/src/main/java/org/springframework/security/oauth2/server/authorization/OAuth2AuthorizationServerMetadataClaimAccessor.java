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

import java.net.URL;
import java.util.List;

import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;

/**
 * A {@link ClaimAccessor} for the "claims" an Authorization Server describes about its
 * configuration, used in OAuth 2.0 Authorization Server Metadata and OpenID Connect
 * Discovery 1.0.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 * @since 0.1.1
 * @see ClaimAccessor
 * @see OAuth2AuthorizationServerMetadataClaimNames
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8414#section-2">2.
 * Authorization Server Metadata</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">3. OpenID
 * Provider Metadata</a>
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
public interface OAuth2AuthorizationServerMetadataClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the {@code URL} the Authorization Server asserts as its Issuer Identifier
	 * {@code (issuer)}.
	 * @return the {@code URL} the Authorization Server asserts as its Issuer Identifier
	 */
	default URL getIssuer() {
		return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.ISSUER);
	}

	/**
	 * Returns the {@code URL} of the OAuth 2.0 Authorization Endpoint
	 * {@code (authorization_endpoint)}.
	 * @return the {@code URL} of the OAuth 2.0 Authorization Endpoint
	 */
	default URL getAuthorizationEndpoint() {
		return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT);
	}

	/**
	 * Returns the {@code URL} of the OAuth 2.0 Pushed Authorization Request Endpoint
	 * {@code (pushed_authorization_request_endpoint)}.
	 * @return the {@code URL} of the OAuth 2.0 Pushed Authorization Request Endpoint
	 * @since 1.5
	 */
	default URL getPushedAuthorizationRequestEndpoint() {
		return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT);
	}

	/**
	 * Returns the {@code URL} of the OAuth 2.0 Device Authorization Endpoint
	 * {@code (device_authorization_endpoint)}.
	 * @return the {@code URL} of the OAuth 2.0 Device Authorization Endpoint
	 * @since 1.1
	 */
	default URL getDeviceAuthorizationEndpoint() {
		return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.DEVICE_AUTHORIZATION_ENDPOINT);
	}

	/**
	 * Returns the {@code URL} of the OAuth 2.0 Token Endpoint {@code (token_endpoint)}.
	 * @return the {@code URL} of the OAuth 2.0 Token Endpoint
	 */
	default URL getTokenEndpoint() {
		return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT);
	}

	/**
	 * Returns the client authentication methods supported by the OAuth 2.0 Token Endpoint
	 * {@code (token_endpoint_auth_methods_supported)}.
	 * @return the client authentication methods supported by the OAuth 2.0 Token Endpoint
	 */
	default List<String> getTokenEndpointAuthenticationMethods() {
		return getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED);
	}

	/**
	 * Returns the {@code URL} of the JSON Web Key Set {@code (jwks_uri)}.
	 * @return the {@code URL} of the JSON Web Key Set
	 */
	default URL getJwkSetUrl() {
		return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI);
	}

	/**
	 * Returns the OAuth 2.0 {@code scope} values supported {@code (scopes_supported)}.
	 * @return the OAuth 2.0 {@code scope} values supported
	 */
	default List<String> getScopes() {
		return getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED);
	}

	/**
	 * Returns the OAuth 2.0 {@code response_type} values supported
	 * {@code (response_types_supported)}.
	 * @return the OAuth 2.0 {@code response_type} values supported
	 */
	default List<String> getResponseTypes() {
		return getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED);
	}

	/**
	 * Returns the OAuth 2.0 {@code grant_type} values supported
	 * {@code (grant_types_supported)}.
	 * @return the OAuth 2.0 {@code grant_type} values supported
	 */
	default List<String> getGrantTypes() {
		return getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED);
	}

	/**
	 * Returns the {@code URL} of the OAuth 2.0 Token Revocation Endpoint
	 * {@code (revocation_endpoint)}.
	 * @return the {@code URL} of the OAuth 2.0 Token Revocation Endpoint
	 */
	default URL getTokenRevocationEndpoint() {
		return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT);
	}

	/**
	 * Returns the client authentication methods supported by the OAuth 2.0 Token
	 * Revocation Endpoint {@code (revocation_endpoint_auth_methods_supported)}.
	 * @return the client authentication methods supported by the OAuth 2.0 Token
	 * Revocation Endpoint
	 */
	default List<String> getTokenRevocationEndpointAuthenticationMethods() {
		return getClaimAsStringList(
				OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED);
	}

	/**
	 * Returns the {@code URL} of the OAuth 2.0 Token Introspection Endpoint
	 * {@code (introspection_endpoint)}.
	 * @return the {@code URL} of the OAuth 2.0 Token Introspection Endpoint
	 */
	default URL getTokenIntrospectionEndpoint() {
		return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT);
	}

	/**
	 * Returns the client authentication methods supported by the OAuth 2.0 Token
	 * Introspection Endpoint {@code (introspection_endpoint_auth_methods_supported)}.
	 * @return the client authentication methods supported by the OAuth 2.0 Token
	 * Introspection Endpoint
	 */
	default List<String> getTokenIntrospectionEndpointAuthenticationMethods() {
		return getClaimAsStringList(
				OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED);
	}

	/**
	 * Returns the {@code URL} of the OAuth 2.0 Dynamic Client Registration Endpoint
	 * {@code (registration_endpoint)}.
	 * @return the {@code URL} of the OAuth 2.0 Dynamic Client Registration Endpoint
	 * @since 0.4.0
	 */
	default URL getClientRegistrationEndpoint() {
		return getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.REGISTRATION_ENDPOINT);
	}

	/**
	 * Returns the Proof Key for Code Exchange (PKCE) {@code code_challenge_method} values
	 * supported {@code (code_challenge_methods_supported)}.
	 * @return the {@code code_challenge_method} values supported
	 */
	default List<String> getCodeChallengeMethods() {
		return getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED);
	}

	/**
	 * Returns {@code true} to indicate support for mutual-TLS client certificate-bound
	 * access tokens {@code (tls_client_certificate_bound_access_tokens)}.
	 * @return {@code true} to indicate support for mutual-TLS client certificate-bound
	 * access tokens, {@code false} otherwise
	 * @since 1.3
	 */
	default boolean isTlsClientCertificateBoundAccessTokens() {
		return Boolean.TRUE.equals(getClaimAsBoolean(
				OAuth2AuthorizationServerMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS));
	}

	/**
	 * Returns the {@link JwsAlgorithms JSON Web Signature (JWS) algorithms} supported for
	 * DPoP Proof JWTs {@code (dpop_signing_alg_values_supported)}.
	 * @return the {@link JwsAlgorithms JSON Web Signature (JWS) algorithms} supported for
	 * DPoP Proof JWTs
	 * @since 1.5
	 */
	default List<String> getDPoPSigningAlgorithms() {
		return getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED);
	}

}
