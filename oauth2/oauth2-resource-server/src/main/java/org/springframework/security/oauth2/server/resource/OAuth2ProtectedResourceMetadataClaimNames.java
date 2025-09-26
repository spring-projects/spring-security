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

package org.springframework.security.oauth2.server.resource;

/**
 * The names of the claims a Resource Server describes about its configuration, used in
 * OAuth 2.0 Protected Resource Metadata.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see <a target="_blank" href="https://www.rfc-editor.org/rfc/rfc9728.html#section-2">2.
 * Protected Resource Metadata</a>
 */
public final class OAuth2ProtectedResourceMetadataClaimNames {

	/**
	 * {@code resource} - the {@code URL} the protected resource asserts as its resource
	 * identifier
	 */
	public static final String RESOURCE = "resource";

	/**
	 * {@code authorization_servers} - a list of {@code issuer} identifier {@code URL}'s,
	 * for authorization servers that can be used with this protected resource
	 */
	public static final String AUTHORIZATION_SERVERS = "authorization_servers";

	/**
	 * {@code scopes_supported} - a list of {@code scope} values supported, that are used
	 * in authorization requests to request access to this protected resource
	 */
	public static final String SCOPES_SUPPORTED = "scopes_supported";

	/**
	 * {@code bearer_methods_supported} - a list of the supported methods for sending an
	 * OAuth 2.0 bearer token to the protected resource. Defined values are "header",
	 * "body" and "query".
	 */
	public static final String BEARER_METHODS_SUPPORTED = "bearer_methods_supported";

	/**
	 * {@code resource_name} - the name of the protected resource intended for display to
	 * the end user
	 */
	public static final String RESOURCE_NAME = "resource_name";

	/**
	 * {@code tls_client_certificate_bound_access_tokens} - {@code true} to indicate
	 * protected resource support for mutual-TLS client certificate-bound access tokens
	 */
	public static final String TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS = "tls_client_certificate_bound_access_tokens";

	private OAuth2ProtectedResourceMetadataClaimNames() {
	}

}
