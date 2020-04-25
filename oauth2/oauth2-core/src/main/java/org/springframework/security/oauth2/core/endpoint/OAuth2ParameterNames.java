/*
 * Copyright 2002-2019 the original author or authors.
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
 * Standard and custom (non-standard) parameter names defined in the OAuth Parameters Registry
 * and used by the authorization endpoint and token endpoint.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-11.2">11.2 OAuth Parameters Registry</a>
 */
public interface OAuth2ParameterNames {

	/**
	 * {@code grant_type} - used in Access Token Request.
	 */
	String GRANT_TYPE = "grant_type";

	/**
	 * {@code response_type} - used in Authorization Request.
	 */
	String RESPONSE_TYPE = "response_type";

	/**
	 * {@code client_id} - used in Authorization Request and Access Token Request.
	 */
	String CLIENT_ID = "client_id";

	/**
	 * {@code client_secret} - used in Access Token Request.
	 */
	String CLIENT_SECRET = "client_secret";

	/**
	 * {@code redirect_uri} - used in Authorization Request and Access Token Request.
	 */
	String REDIRECT_URI = "redirect_uri";

	/**
	 * {@code scope} - used in Authorization Request, Authorization Response, Access Token Request and Access Token Response.
	 */
	String SCOPE = "scope";

	/**
	 * {@code state} - used in Authorization Request and Authorization Response.
	 */
	String STATE = "state";

	/**
	 * {@code code} - used in Authorization Response and Access Token Request.
	 */
	String CODE = "code";

	/**
	 * {@code access_token} - used in Authorization Response and Access Token Response.
	 */
	String ACCESS_TOKEN = "access_token";

	/**
	 * {@code token_type} - used in Authorization Response and Access Token Response.
	 */
	String TOKEN_TYPE = "token_type";

	/**
	 * {@code expires_in} - used in Authorization Response and Access Token Response.
	 */
	String EXPIRES_IN = "expires_in";

	/**
	 * {@code refresh_token} - used in Access Token Request and Access Token Response.
	 */
	String REFRESH_TOKEN = "refresh_token";

	/**
	 * {@code username} - used in Access Token Request.
	 */
	String USERNAME = "username";

	/**
	 * {@code password} - used in Access Token Request.
	 */
	String PASSWORD = "password";

	/**
	 * {@code client_assertion} - used in Access Token Request.
	 */
	String CLIENT_ASSERTION = "client_assertion";

	/**
	 * {@code client_assertion} - used in Access Token Request.
	 */
	String CLIENT_ASSERTION_TYPE = "client_assertion_type";

	/**
	 * {@code error} - used in Authorization Response and Access Token Response.
	 */
	String ERROR = "error";

	/**
	 * {@code error_description} - used in Authorization Response and Access Token Response.
	 */
	String ERROR_DESCRIPTION = "error_description";

	/**
	 * {@code error_uri} - used in Authorization Response and Access Token Response.
	 */
	String ERROR_URI = "error_uri";

	/**
	 * Non-standard parameter (used internally).
	 */
	String REGISTRATION_ID = "registration_id";

}
