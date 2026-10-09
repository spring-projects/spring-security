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

package org.springframework.security.oauth2.server.authorization.authentication;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * A strategy for resolving an externally-issued subject token into an
 * {@link OAuth2TokenExchangeSubjectTokenContext} during the OAuth 2.0 Token Exchange
 * Grant.
 *
 * <p>
 * Implementations of this interface are responsible for validating and decoding the
 * subject token (e.g., an externally-issued ID token) and constructing the authorization
 * and principal context needed for token exchange.
 *
 * <p>
 * <b>NOTE:</b> When this resolver returns a non-{@code null} context, the
 * {@link OAuth2TokenExchangeAuthenticationProvider} constructs a synthetic
 * {@link org.springframework.security.oauth2.server.authorization.OAuth2Authorization}
 * that contains only the principal name and principal attribute. This synthetic
 * authorization does not contain an access token or other token metadata. Token
 * generators or customizers that inspect the authorization's tokens should account for
 * this.
 *
 * @author Bapuji Koraganti
 * @since 7.0
 * @see OAuth2TokenExchangeAuthenticationProvider
 * @see OAuth2TokenExchangeSubjectTokenContext
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc8693#section-2.1">Section 2.1 Request</a>
 */
@FunctionalInterface
public interface OAuth2TokenExchangeSubjectTokenResolver {

	/**
	 * Resolves the subject token into an {@link OAuth2TokenExchangeSubjectTokenContext}.
	 * Returns {@code null} if this resolver cannot handle the given token type.
	 * @param subjectToken the subject token value
	 * @param subjectTokenType the token type identifier (e.g.,
	 * {@code urn:ietf:params:oauth:token-type:id_token})
	 * @param registeredClient the registered client performing the token exchange
	 * @return the resolved subject token context, or {@code null} if not supported
	 */
	@Nullable OAuth2TokenExchangeSubjectTokenContext resolve(String subjectToken, String subjectTokenType,
			RegisteredClient registeredClient);

}
