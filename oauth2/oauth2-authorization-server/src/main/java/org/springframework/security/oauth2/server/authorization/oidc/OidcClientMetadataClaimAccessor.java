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

import java.net.URL;
import java.util.List;

import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientMetadataClaimAccessor;

/**
 * A {@link ClaimAccessor} for the "claims" that are contained in the OpenID Client
 * Registration Request and Response.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2ClientMetadataClaimAccessor
 * @see OidcClientMetadataClaimNames
 * @see OidcClientRegistration
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata">2.
 * Client Metadata</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ClientMetadata">3.1.
 * Client Registration Metadata</a>
 */
public interface OidcClientMetadataClaimAccessor extends OAuth2ClientMetadataClaimAccessor {

	/**
	 * Returns the post logout redirection {@code URI} values used by the Client
	 * {@code (post_logout_redirect_uris)}. The {@code post_logout_redirect_uri} parameter
	 * is used by the client when requesting that the End-User's User Agent be redirected
	 * to after a logout has been performed.
	 * @return the post logout redirection {@code URI} values used by the Client
	 */
	default List<String> getPostLogoutRedirectUris() {
		return getClaimAsStringList(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS);
	}

	/**
	 * Returns the {@link JwsAlgorithm JWS} algorithm that must be used for signing the
	 * {@link Jwt JWT} used to authenticate the Client at the Token Endpoint for the
	 * {@link ClientAuthenticationMethod#PRIVATE_KEY_JWT private_key_jwt} and
	 * {@link ClientAuthenticationMethod#CLIENT_SECRET_JWT client_secret_jwt}
	 * authentication methods {@code (token_endpoint_auth_signing_alg)}.
	 * @return the {@link JwsAlgorithm JWS} algorithm that must be used for signing the
	 * {@link Jwt JWT} used to authenticate the Client at the Token Endpoint
	 */
	default String getTokenEndpointAuthenticationSigningAlgorithm() {
		return getClaimAsString(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_SIGNING_ALG);
	}

	/**
	 * Returns the {@link SignatureAlgorithm JWS} algorithm required for signing the
	 * {@link OidcIdToken ID Token} issued to the Client
	 * {@code (id_token_signed_response_alg)}.
	 * @return the {@link SignatureAlgorithm JWS} algorithm required for signing the
	 * {@link OidcIdToken ID Token} issued to the Client
	 */
	default String getIdTokenSignedResponseAlgorithm() {
		return getClaimAsString(OidcClientMetadataClaimNames.ID_TOKEN_SIGNED_RESPONSE_ALG);
	}

	/**
	 * Returns the Registration Access Token that can be used at the Client Configuration
	 * Endpoint.
	 * @return the Registration Access Token that can be used at the Client Configuration
	 * Endpoint
	 */
	default String getRegistrationAccessToken() {
		return getClaimAsString(OidcClientMetadataClaimNames.REGISTRATION_ACCESS_TOKEN);
	}

	/**
	 * Returns the {@code URL} of the Client Configuration Endpoint where the Registration
	 * Access Token can be used.
	 * @return the {@code URL} of the Client Configuration Endpoint where the Registration
	 * Access Token can be used
	 */
	default URL getRegistrationClientUrl() {
		return getClaimAsURL(OidcClientMetadataClaimNames.REGISTRATION_CLIENT_URI);
	}

}
