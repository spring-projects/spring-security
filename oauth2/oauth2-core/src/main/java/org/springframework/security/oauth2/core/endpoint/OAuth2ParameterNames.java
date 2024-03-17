/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.oauth2.core.endpoint;

/**
 * Standard and custom (non-standard) parameter names defined in the OAuth Parameters
 * Registry and used by the authorization endpoint, token endpoint and token revocation
 * endpoint.
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-11.2">11.2
 * OAuth Parameters Registry</a>
 */
public final class OAuth2ParameterNames {

	/**
	 * {@code grant_type} - used in Access Token Request.
	 */
	public static final String GRANT_TYPE = "grant_type";

	/**
	 * {@code response_type} - used in Authorization Request.
	 */
	public static final String RESPONSE_TYPE = "response_type";

	/**
	 * {@code client_id} - used in Authorization Request and Access Token Request.
	 */
	public static final String CLIENT_ID = "client_id";

	/**
	 * {@code client_secret} - used in Access Token Request.
	 */
	public static final String CLIENT_SECRET = "client_secret";

	/**
	 * {@code client_assertion_type} - used in Access Token Request.
	 * @since 5.5
	 */
	public static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";

	/**
	 * {@code client_assertion} - used in Access Token Request.
	 * @since 5.5
	 */
	public static final String CLIENT_ASSERTION = "client_assertion";

	/**
	 * {@code assertion} - used in Access Token Request.
	 * @since 5.5
	 */
	public static final String ASSERTION = "assertion";

	/**
	 * {@code redirect_uri} - used in Authorization Request and Access Token Request.
	 */
	public static final String REDIRECT_URI = "redirect_uri";

	/**
	 * {@code scope} - used in Authorization Request, Authorization Response, Access Token
	 * Request and Access Token Response.
	 */
	public static final String SCOPE = "scope";

	/**
	 * {@code state} - used in Authorization Request and Authorization Response.
	 */
	public static final String STATE = "state";

	/**
	 * {@code code} - used in Authorization Response and Access Token Request.
	 */
	public static final String CODE = "code";

	/**
	 * {@code access_token} - used in Authorization Response and Access Token Response.
	 */
	public static final String ACCESS_TOKEN = "access_token";

	/**
	 * {@code token_type} - used in Authorization Response and Access Token Response.
	 */
	public static final String TOKEN_TYPE = "token_type";

	/**
	 * {@code expires_in} - used in Authorization Response and Access Token Response.
	 */
	public static final String EXPIRES_IN = "expires_in";

	/**
	 * {@code refresh_token} - used in Access Token Request and Access Token Response.
	 */
	public static final String REFRESH_TOKEN = "refresh_token";

	/**
	 * {@code username} - used in Access Token Request.
	 */
	public static final String USERNAME = "username";

	/**
	 * {@code password} - used in Access Token Request.
	 */
	public static final String PASSWORD = "password";

	/**
	 * {@code error} - used in Authorization Response and Access Token Response.
	 */
	public static final String ERROR = "error";

	/**
	 * {@code error_description} - used in Authorization Response and Access Token
	 * Response.
	 */
	public static final String ERROR_DESCRIPTION = "error_description";

	/**
	 * {@code error_uri} - used in Authorization Response and Access Token Response.
	 */
	public static final String ERROR_URI = "error_uri";

	/**
	 * Non-standard parameter (used internally).
	 */
	public static final String REGISTRATION_ID = "registration_id";

	/**
	 * {@code token} - used in Token Revocation Request.
	 * @since 5.5
	 */
	public static final String TOKEN = "token";

	/**
	 * {@code token_type_hint} - used in Token Revocation Request.
	 * @since 5.5
	 */
	public static final String TOKEN_TYPE_HINT = "token_type_hint";

	/**
	 * {@code device_code} - used in Device Authorization Response and Device Access Token
	 * Request.
	 * @since 6.1
	 */
	public static final String DEVICE_CODE = "device_code";

	/**
	 * {@code user_code} - used in Device Authorization Response.
	 * @since 6.1
	 */
	public static final String USER_CODE = "user_code";

	/**
	 * {@code verification_uri} - used in Device Authorization Response.
	 * @since 6.1
	 */
	public static final String VERIFICATION_URI = "verification_uri";

	/**
	 * {@code verification_uri_complete} - used in Device Authorization Response.
	 * @since 6.1
	 */
	public static final String VERIFICATION_URI_COMPLETE = "verification_uri_complete";

	/**
	 * {@code interval} - used in Device Authorization Response.
	 * @since 6.1
	 */
	public static final String INTERVAL = "interval";

	/**
	 * {@code audience} - used in Token Exchange Access Token Request.
	 * @since 6.3
	 */
	public static final String AUDIENCE = "audience";

	/**
	 * {@code resource} - used in Token Exchange Access Token Request.
	 * @since 6.3
	 */
	public static final String RESOURCE = "resource";

	/**
	 * {@code requested_token_type} - used in Token Exchange Access Token Request.
	 * @since 6.3
	 */
	public static final String REQUESTED_TOKEN_TYPE = "requested_token_type";

	/**
	 * {@code issued_token_type} - used in Token Exchange Access Token Response.
	 * @since 6.3
	 */
	public static final String ISSUED_TOKEN_TYPE = "issued_token_type";

	/**
	 * {@code subject_token} - used in Token Exchange Access Token Request.
	 * @since 6.3
	 */
	public static final String SUBJECT_TOKEN = "subject_token";

	/**
	 * {@code subject_token_type} - used in Token Exchange Access Token Request.
	 * @since 6.3
	 */
	public static final String SUBJECT_TOKEN_TYPE = "subject_token_type";

	/**
	 * {@code actor_token} - used in Token Exchange Access Token Request.
	 * @since 6.3
	 */
	public static final String ACTOR_TOKEN = "actor_token";

	/**
	 * {@code actor_token_type} - used in Token Exchange Access Token Request.
	 * @since 6.3
	 */
	public static final String ACTOR_TOKEN_TYPE = "actor_token_type";

	private OAuth2ParameterNames() {
	}

}
