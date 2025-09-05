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

import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;

/**
 * The names of the "claims" an Authorization Server describes about its configuration,
 * used in OAuth 2.0 Authorization Server Metadata and OpenID Connect Discovery 1.0.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 * @since 0.1.1
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
public class OAuth2AuthorizationServerMetadataClaimNames {

	/**
	 * {@code issuer} - the {@code URL} the Authorization Server asserts as its Issuer
	 * Identifier
	 */
	public static final String ISSUER = "issuer";

	/**
	 * {@code authorization_endpoint} - the {@code URL} of the OAuth 2.0 Authorization
	 * Endpoint
	 */
	public static final String AUTHORIZATION_ENDPOINT = "authorization_endpoint";

	/**
	 * {@code pushed_authorization_request_endpoint} - the {@code URL} of the OAuth 2.0
	 * Pushed Authorization Request Endpoint
	 * @since 1.5
	 */
	public static final String PUSHED_AUTHORIZATION_REQUEST_ENDPOINT = "pushed_authorization_request_endpoint";

	/**
	 * {@code device_authorization_endpoint} - the {@code URL} of the OAuth 2.0 Device
	 * Authorization Endpoint
	 * @since 1.1
	 */
	public static final String DEVICE_AUTHORIZATION_ENDPOINT = "device_authorization_endpoint";

	/**
	 * {@code token_endpoint} - the {@code URL} of the OAuth 2.0 Token Endpoint
	 */
	public static final String TOKEN_ENDPOINT = "token_endpoint";

	/**
	 * {@code token_endpoint_auth_methods_supported} - the client authentication methods
	 * supported by the OAuth 2.0 Token Endpoint
	 */
	public static final String TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = "token_endpoint_auth_methods_supported";

	/**
	 * {@code jwks_uri} - the {@code URL} of the JSON Web Key Set
	 */
	public static final String JWKS_URI = "jwks_uri";

	/**
	 * {@code scopes_supported} - the OAuth 2.0 {@code scope} values supported
	 */
	public static final String SCOPES_SUPPORTED = "scopes_supported";

	/**
	 * {@code response_types_supported} - the OAuth 2.0 {@code response_type} values
	 * supported
	 */
	public static final String RESPONSE_TYPES_SUPPORTED = "response_types_supported";

	/**
	 * {@code grant_types_supported} - the OAuth 2.0 {@code grant_type} values supported
	 */
	public static final String GRANT_TYPES_SUPPORTED = "grant_types_supported";

	/**
	 * {@code revocation_endpoint} - the {@code URL} of the OAuth 2.0 Token Revocation
	 * Endpoint
	 */
	public static final String REVOCATION_ENDPOINT = "revocation_endpoint";

	/**
	 * {@code revocation_endpoint_auth_methods_supported} - the client authentication
	 * methods supported by the OAuth 2.0 Token Revocation Endpoint
	 */
	public static final String REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED = "revocation_endpoint_auth_methods_supported";

	/**
	 * {@code introspection_endpoint} - the {@code URL} of the OAuth 2.0 Token
	 * Introspection Endpoint
	 */
	public static final String INTROSPECTION_ENDPOINT = "introspection_endpoint";

	/**
	 * {@code introspection_endpoint_auth_methods_supported} - the client authentication
	 * methods supported by the OAuth 2.0 Token Introspection Endpoint
	 */
	public static final String INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED = "introspection_endpoint_auth_methods_supported";

	/**
	 * {@code registration_endpoint} - the {@code URL} of the OAuth 2.0 Dynamic Client
	 * Registration Endpoint
	 * @since 0.4.0
	 */
	public static final String REGISTRATION_ENDPOINT = "registration_endpoint";

	/**
	 * {@code code_challenge_methods_supported} - the Proof Key for Code Exchange (PKCE)
	 * {@code code_challenge_method} values supported
	 */
	public static final String CODE_CHALLENGE_METHODS_SUPPORTED = "code_challenge_methods_supported";

	/**
	 * {@code tls_client_certificate_bound_access_tokens} - {@code true} to indicate
	 * support for mutual-TLS client certificate-bound access tokens
	 * @since 1.3
	 */
	public static final String TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS = "tls_client_certificate_bound_access_tokens";

	/**
	 * {@code dpop_signing_alg_values_supported} - the {@link JwsAlgorithms JSON Web
	 * Signature (JWS) algorithms} supported for DPoP Proof JWTs
	 * @since 1.5
	 */
	public static final String DPOP_SIGNING_ALG_VALUES_SUPPORTED = "dpop_signing_alg_values_supported";

	protected OAuth2AuthorizationServerMetadataClaimNames() {
	}

}
