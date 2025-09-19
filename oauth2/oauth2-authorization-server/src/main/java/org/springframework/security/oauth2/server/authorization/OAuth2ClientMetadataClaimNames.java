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

/**
 * The names of the claims defined by OAuth 2.0 Dynamic Client Registration Protocol that
 * are contained in the OAuth 2.0 Client Registration Request and Response.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc7591#section-2">2. Client Metadata</a>
 */
public class OAuth2ClientMetadataClaimNames {

	/**
	 * {@code client_id} - the Client Identifier
	 */
	public static final String CLIENT_ID = "client_id";

	/**
	 * {@code client_id_issued_at} - the time at which the Client Identifier was issued
	 */
	public static final String CLIENT_ID_ISSUED_AT = "client_id_issued_at";

	/**
	 * {@code client_secret} - the Client Secret
	 */
	public static final String CLIENT_SECRET = "client_secret";

	/**
	 * {@code client_secret_expires_at} - the time at which the {@code client_secret} will
	 * expire or 0 if it will not expire
	 */
	public static final String CLIENT_SECRET_EXPIRES_AT = "client_secret_expires_at";

	/**
	 * {@code client_name} - the name of the Client to be presented to the End-User
	 */
	public static final String CLIENT_NAME = "client_name";

	/**
	 * {@code redirect_uris} - the redirection {@code URI} values used by the Client
	 */
	public static final String REDIRECT_URIS = "redirect_uris";

	/**
	 * {@code token_endpoint_auth_method} - the authentication method used by the Client
	 * for the Token Endpoint
	 */
	public static final String TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";

	/**
	 * {@code grant_types} - the OAuth 2.0 {@code grant_type} values that the Client will
	 * restrict itself to using
	 */
	public static final String GRANT_TYPES = "grant_types";

	/**
	 * {@code response_types} - the OAuth 2.0 {@code response_type} values that the Client
	 * will restrict itself to using
	 */
	public static final String RESPONSE_TYPES = "response_types";

	/**
	 * {@code scope} - a space-separated list of OAuth 2.0 {@code scope} values that the
	 * Client will restrict itself to using
	 */
	public static final String SCOPE = "scope";

	/**
	 * {@code jwks_uri} - the {@code URL} for the Client's JSON Web Key Set
	 */
	public static final String JWKS_URI = "jwks_uri";

	protected OAuth2ClientMetadataClaimNames() {
	}

}
