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

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * The names for all the configuration settings.
 *
 * @author Joe Grandja
 * @since 0.2.0
 */
public final class ConfigurationSettingNames {

	private static final String SETTINGS_NAMESPACE = "settings.";

	private ConfigurationSettingNames() {
	}

	/**
	 * The names for client configuration settings.
	 */
	public static final class Client {

		private static final String CLIENT_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE.concat("client.");

		/**
		 * Set to {@code true} if the client is required to provide a proof key challenge
		 * and verifier when performing the Authorization Code Grant flow.
		 */
		public static final String REQUIRE_PROOF_KEY = CLIENT_SETTINGS_NAMESPACE.concat("require-proof-key");

		/**
		 * Set to {@code true} if authorization consent is required when the client
		 * requests access. This applies to all interactive flows (e.g.
		 * {@code authorization_code} and {@code device_code}).
		 */
		public static final String REQUIRE_AUTHORIZATION_CONSENT = CLIENT_SETTINGS_NAMESPACE
			.concat("require-authorization-consent");

		/**
		 * Set the {@code URL} for the Client's JSON Web Key Set.
		 * @since 0.2.2
		 */
		public static final String JWK_SET_URL = CLIENT_SETTINGS_NAMESPACE.concat("jwk-set-url");

		/**
		 * Set the {@link JwsAlgorithm JWS} algorithm that must be used for signing the
		 * {@link Jwt JWT} used to authenticate the Client at the Token Endpoint for the
		 * {@link ClientAuthenticationMethod#PRIVATE_KEY_JWT private_key_jwt} and
		 * {@link ClientAuthenticationMethod#CLIENT_SECRET_JWT client_secret_jwt}
		 * authentication methods.
		 * @since 0.2.2
		 */
		public static final String TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM = CLIENT_SETTINGS_NAMESPACE
			.concat("token-endpoint-authentication-signing-algorithm");

		/**
		 * Set the expected subject distinguished name associated to the client
		 * {@code X509Certificate} received during client authentication when using the
		 * {@code tls_client_auth} method.
		 * @since 1.3
		 */
		public static final String X509_CERTIFICATE_SUBJECT_DN = CLIENT_SETTINGS_NAMESPACE
			.concat("x509-certificate-subject-dn");

		private Client() {
		}

	}

	/**
	 * The names for authorization server configuration settings.
	 */
	public static final class AuthorizationServer {

		private static final String AUTHORIZATION_SERVER_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE
			.concat("authorization-server.");

		/**
		 * Set the URL the Authorization Server uses as its Issuer Identifier.
		 */
		public static final String ISSUER = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE.concat("issuer");

		/**
		 * Set to {@code true} if multiple issuers are allowed per host.
		 * @since 1.3
		 */
		public static final String MULTIPLE_ISSUERS_ALLOWED = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("multiple-issuers-allowed");

		/**
		 * Set the OAuth 2.0 Authorization endpoint.
		 */
		public static final String AUTHORIZATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("authorization-endpoint");

		/**
		 * Set the OAuth 2.0 Pushed Authorization Request endpoint.
		 * @since 1.5
		 */
		public static final String PUSHED_AUTHORIZATION_REQUEST_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("pushed-authorization-request-endpoint");

		/**
		 * Set the OAuth 2.0 Device Authorization endpoint.
		 */
		public static final String DEVICE_AUTHORIZATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("device-authorization-endpoint");

		/**
		 * Set the OAuth 2.0 Device Verification endpoint.
		 */
		public static final String DEVICE_VERIFICATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("device-verification-endpoint");

		/**
		 * Set the OAuth 2.0 Token endpoint.
		 */
		public static final String TOKEN_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE.concat("token-endpoint");

		/**
		 * Set the JWK Set endpoint.
		 */
		public static final String JWK_SET_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("jwk-set-endpoint");

		/**
		 * Set the OAuth 2.0 Token Revocation endpoint.
		 */
		public static final String TOKEN_REVOCATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("token-revocation-endpoint");

		/**
		 * Set the OAuth 2.0 Token Introspection endpoint.
		 */
		public static final String TOKEN_INTROSPECTION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("token-introspection-endpoint");

		/**
		 * Set the OpenID Connect 1.0 Client Registration endpoint.
		 */
		public static final String OIDC_CLIENT_REGISTRATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("oidc-client-registration-endpoint");

		/**
		 * Set the OpenID Connect 1.0 UserInfo endpoint.
		 */
		public static final String OIDC_USER_INFO_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("oidc-user-info-endpoint");

		/**
		 * Set the OpenID Connect 1.0 Logout endpoint.
		 * @since 1.1
		 */
		public static final String OIDC_LOGOUT_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("oidc-logout-endpoint");

		private AuthorizationServer() {
		}

	}

	/**
	 * The names for token configuration settings.
	 */
	public static final class Token {

		private static final String TOKEN_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE.concat("token.");

		/**
		 * Set the time-to-live for an authorization code.
		 * @since 0.4.0
		 */
		public static final String AUTHORIZATION_CODE_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE
			.concat("authorization-code-time-to-live");

		/**
		 * Set the time-to-live for an access token.
		 */
		public static final String ACCESS_TOKEN_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE
			.concat("access-token-time-to-live");

		/**
		 * Set the {@link OAuth2TokenFormat token format} for an access token.
		 * @since 0.2.3
		 */
		public static final String ACCESS_TOKEN_FORMAT = TOKEN_SETTINGS_NAMESPACE.concat("access-token-format");

		/**
		 * Set the time-to-live for a device code.
		 * @since 1.1
		 */
		public static final String DEVICE_CODE_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE
			.concat("device-code-time-to-live");

		/**
		 * Set to {@code true} if refresh tokens are reused when returning the access
		 * token response, or {@code false} if a new refresh token is issued.
		 */
		public static final String REUSE_REFRESH_TOKENS = TOKEN_SETTINGS_NAMESPACE.concat("reuse-refresh-tokens");

		/**
		 * Set the time-to-live for a refresh token.
		 */
		public static final String REFRESH_TOKEN_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE
			.concat("refresh-token-time-to-live");

		/**
		 * Set the {@link SignatureAlgorithm JWS} algorithm for signing the
		 * {@link OidcIdToken ID Token}.
		 */
		public static final String ID_TOKEN_SIGNATURE_ALGORITHM = TOKEN_SETTINGS_NAMESPACE
			.concat("id-token-signature-algorithm");

		/**
		 * Set to {@code true} if access tokens must be bound to the client
		 * {@code X509Certificate} received during client authentication when using the
		 * {@code tls_client_auth} or {@code self_signed_tls_client_auth} method.
		 * @since 1.3
		 */
		public static final String X509_CERTIFICATE_BOUND_ACCESS_TOKENS = TOKEN_SETTINGS_NAMESPACE
			.concat("x509-certificate-bound-access-tokens");

		private Token() {
		}

	}

}
