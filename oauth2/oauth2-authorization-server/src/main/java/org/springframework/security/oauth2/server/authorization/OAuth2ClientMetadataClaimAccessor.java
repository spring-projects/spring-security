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
import java.time.Instant;
import java.util.List;

import org.springframework.security.oauth2.core.ClaimAccessor;

/**
 * A {@link ClaimAccessor} for the claims that are contained in the OAuth 2.0 Client
 * Registration Request and Response.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see ClaimAccessor
 * @see OAuth2ClientMetadataClaimNames
 * @see OAuth2ClientRegistration
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc7591#section-2">2. Client Metadata</a>
 */
public interface OAuth2ClientMetadataClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the Client Identifier {@code (client_id)}.
	 * @return the Client Identifier
	 */
	default String getClientId() {
		return getClaimAsString(OAuth2ClientMetadataClaimNames.CLIENT_ID);
	}

	/**
	 * Returns the time at which the Client Identifier was issued
	 * {@code (client_id_issued_at)}.
	 * @return the time at which the Client Identifier was issued
	 */
	default Instant getClientIdIssuedAt() {
		return getClaimAsInstant(OAuth2ClientMetadataClaimNames.CLIENT_ID_ISSUED_AT);
	}

	/**
	 * Returns the Client Secret {@code (client_secret)}.
	 * @return the Client Secret
	 */
	default String getClientSecret() {
		return getClaimAsString(OAuth2ClientMetadataClaimNames.CLIENT_SECRET);
	}

	/**
	 * Returns the time at which the {@code client_secret} will expire
	 * {@code (client_secret_expires_at)}.
	 * @return the time at which the {@code client_secret} will expire
	 */
	default Instant getClientSecretExpiresAt() {
		return getClaimAsInstant(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT);
	}

	/**
	 * Returns the name of the Client to be presented to the End-User
	 * {@code (client_name)}.
	 * @return the name of the Client to be presented to the End-User
	 */
	default String getClientName() {
		return getClaimAsString(OAuth2ClientMetadataClaimNames.CLIENT_NAME);
	}

	/**
	 * Returns the redirection {@code URI} values used by the Client
	 * {@code (redirect_uris)}.
	 * @return the redirection {@code URI} values used by the Client
	 */
	default List<String> getRedirectUris() {
		return getClaimAsStringList(OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
	}

	/**
	 * Returns the authentication method used by the Client for the Token Endpoint
	 * {@code (token_endpoint_auth_method)}.
	 * @return the authentication method used by the Client for the Token Endpoint
	 */
	default String getTokenEndpointAuthenticationMethod() {
		return getClaimAsString(OAuth2ClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
	}

	/**
	 * Returns the OAuth 2.0 {@code grant_type} values that the Client will restrict
	 * itself to using {@code (grant_types)}.
	 * @return the OAuth 2.0 {@code grant_type} values that the Client will restrict
	 * itself to using
	 */
	default List<String> getGrantTypes() {
		return getClaimAsStringList(OAuth2ClientMetadataClaimNames.GRANT_TYPES);
	}

	/**
	 * Returns the OAuth 2.0 {@code response_type} values that the Client will restrict
	 * itself to using {@code (response_types)}.
	 * @return the OAuth 2.0 {@code response_type} values that the Client will restrict
	 * itself to using
	 */
	default List<String> getResponseTypes() {
		return getClaimAsStringList(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES);
	}

	/**
	 * Returns the OAuth 2.0 {@code scope} values that the Client will restrict itself to
	 * using {@code (scope)}.
	 * @return the OAuth 2.0 {@code scope} values that the Client will restrict itself to
	 * using
	 */
	default List<String> getScopes() {
		return getClaimAsStringList(OAuth2ClientMetadataClaimNames.SCOPE);
	}

	/**
	 * Returns the {@code URL} for the Client's JSON Web Key Set {@code (jwks_uri)}.
	 * @return the {@code URL} for the Client's JSON Web Key Set {@code (jwks_uri)}
	 */
	default URL getJwkSetUrl() {
		return getClaimAsURL(OAuth2ClientMetadataClaimNames.JWKS_URI);
	}

}
