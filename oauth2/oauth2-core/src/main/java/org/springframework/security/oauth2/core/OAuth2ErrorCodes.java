/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.oauth2.core;

/**
 * Standard error codes defined by the OAuth 2.0 Authorization Framework.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public interface OAuth2ErrorCodes {

	/**
	 * {@code invalid_request} - The request is missing a required parameter, includes an
	 * invalid parameter value, includes a parameter more than once, or is otherwise
	 * malformed.
	 */
	String INVALID_REQUEST = "invalid_request";

	/**
	 * {@code unauthorized_client} - The client is not authorized to request an
	 * authorization code or access token using this method.
	 */
	String UNAUTHORIZED_CLIENT = "unauthorized_client";

	/**
	 * {@code access_denied} - The resource owner or authorization server denied the
	 * request.
	 */
	String ACCESS_DENIED = "access_denied";

	/**
	 * {@code unsupported_response_type} - The authorization server does not support
	 * obtaining an authorization code or access token using this method.
	 */
	String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";

	/**
	 * {@code invalid_scope} - The requested scope is invalid, unknown, malformed or
	 * exceeds the scope granted by the resource owner.
	 */
	String INVALID_SCOPE = "invalid_scope";

	/**
	 * {@code insufficient_scope} - The request requires higher privileges than provided
	 * by the access token. The resource server SHOULD respond with the HTTP 403
	 * (Forbidden) status code and MAY include the "scope" attribute with the scope
	 * necessary to access the protected resource.
	 *
	 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3.1">RFC-6750 - Section
	 * 3.1 - Error Codes</a>
	 */
	String INSUFFICIENT_SCOPE = "insufficient_scope";

	/**
	 * {@code invalid_token} - The access token provided is expired, revoked, malformed,
	 * or invalid for other reasons. The resource SHOULD respond with the HTTP 401
	 * (Unauthorized) status code. The client MAY request a new access token and retry the
	 * protected resource request.
	 *
	 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3.1">RFC-6750 - Section
	 * 3.1 - Error Codes</a>
	 */
	String INVALID_TOKEN = "invalid_token";

	/**
	 * {@code server_error} - The authorization server encountered an unexpected condition
	 * that prevented it from fulfilling the request. (This error code is needed because a
	 * 500 Internal Server Error HTTP status code cannot be returned to the client via a
	 * HTTP redirect.)
	 */
	String SERVER_ERROR = "server_error";

	/**
	 * {@code temporarily_unavailable} - The authorization server is currently unable to
	 * handle the request due to a temporary overloading or maintenance of the server.
	 * (This error code is needed because a 503 Service Unavailable HTTP status code
	 * cannot be returned to the client via an HTTP redirect.)
	 */
	String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";

	/**
	 * {@code invalid_client} - Client authentication failed (e.g., unknown client, no
	 * client authentication included, or unsupported authentication method). The
	 * authorization server MAY return a HTTP 401 (Unauthorized) status code to indicate
	 * which HTTP authentication schemes are supported. If the client attempted to
	 * authenticate via the &quot;Authorization&quot; request header field, the
	 * authorization server MUST respond with a HTTP 401 (Unauthorized) status code and
	 * include the &quot;WWW-Authenticate&quot; response header field matching the
	 * authentication scheme used by the client.
	 */
	String INVALID_CLIENT = "invalid_client";

	/**
	 * {@code invalid_grant} - The provided authorization grant (e.g., authorization code,
	 * resource owner credentials) or refresh token is invalid, expired, revoked, does not
	 * match the redirection URI used in the authorization request, or was issued to
	 * another client.
	 */
	String INVALID_GRANT = "invalid_grant";

	/**
	 * {@code unsupported_grant_type} - The authorization grant type is not supported by
	 * the authorization server.
	 */
	String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";

}
