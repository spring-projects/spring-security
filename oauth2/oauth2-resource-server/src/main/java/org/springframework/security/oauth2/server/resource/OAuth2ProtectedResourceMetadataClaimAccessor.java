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

import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.oauth2.core.ClaimAccessor;

/**
 * A {@link ClaimAccessor} for the claims a Resource Server describes about its
 * configuration, used in OAuth 2.0 Protected Resource Metadata.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see ClaimAccessor
 * @see OAuth2ProtectedResourceMetadataClaimNames
 * @see <a target="_blank" href="https://www.rfc-editor.org/rfc/rfc9728.html#section-2">2.
 * Protected Resource Metadata</a>
 */
public interface OAuth2ProtectedResourceMetadataClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the {@code URL} the protected resource asserts as its resource identifier
	 * {@code (resource)}.
	 * @return the {@code URL} the protected resource asserts as its resource identifier
	 */
	default URL getResource() {
		return getClaimAsURL(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE);
	}

	/**
	 * Returns a list of {@code issuer} identifier {@code URL}'s, for authorization
	 * servers that can be used with this protected resource
	 * {@code (authorization_servers)}.
	 * @return a list of {@code issuer} identifier {@code URL}'s, for authorization
	 * servers that can be used with this protected resource
	 */
	default List<URL> getAuthorizationServers() {
		List<String> authorizationServers = getClaimAsStringList(
				OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS);
		List<URL> urls = new ArrayList<>();
		authorizationServers.forEach((authorizationServer) -> {
			try {
				urls.add(new URI(authorizationServer).toURL());
			}
			catch (Exception ex) {
				throw new IllegalArgumentException("Failed to convert authorization_server to URL", ex);
			}
		});
		return urls;
	}

	/**
	 * Returns a list of {@code scope} values supported, that are used in authorization
	 * requests to request access to this protected resource {@code (scopes_supported)}.
	 * @return a list of {@code scope} values supported, that are used in authorization
	 * requests to request access to this protected resource
	 */
	default List<String> getScopes() {
		return getClaimAsStringList(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED);
	}

	/**
	 * Returns a list of the supported methods for sending an OAuth 2.0 bearer token to
	 * the protected resource. Defined values are "header", "body" and "query".
	 * {@code (bearer_methods_supported)}.
	 * @return a list of the supported methods for sending an OAuth 2.0 bearer token to
	 * the protected resource
	 */
	default List<String> getBearerMethodsSupported() {
		return getClaimAsStringList(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED);
	}

	/**
	 * Returns the name of the protected resource intended for display to the end user
	 * {@code (resource_name)}.
	 * @return the name of the protected resource intended for display to the end user
	 */
	default String getResourceName() {
		return getClaimAsString(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE_NAME);
	}

	/**
	 * Returns {@code true} to indicate protected resource support for mutual-TLS client
	 * certificate-bound access tokens
	 * {@code (tls_client_certificate_bound_access_tokens)}.
	 * @return {@code true} to indicate protected resource support for mutual-TLS client
	 * certificate-bound access tokens
	 */
	default boolean isTlsClientCertificateBoundAccessTokens() {
		return Boolean.TRUE.equals(getClaimAsBoolean(
				OAuth2ProtectedResourceMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS));
	}

}
