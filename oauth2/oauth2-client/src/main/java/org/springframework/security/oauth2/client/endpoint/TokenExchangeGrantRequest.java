/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.client.endpoint;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.util.Assert;

/**
 * A Token Exchange Grant request that holds the {@link OAuth2Token subject token} and
 * optional {@link OAuth2Token actor token}.
 *
 * @author Steve Riesenberg
 * @since 6.3
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see ClientRegistration
 * @see OAuth2Token
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8693#section-1.1">Section
 * 1.1 Delegation vs. Impersonation Semantics</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8693#section-2.1">Section
 * 2.1 Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8693#section-2.2">Section
 * 2.2 Response</a>
 */
public class TokenExchangeGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

	private final OAuth2Token subjectToken;

	private final OAuth2Token actorToken;

	/**
	 * Constructs a {@code TokenExchangeGrantRequest} using the provided parameters.
	 * @param clientRegistration the client registration
	 * @param subjectToken the subject token
	 * @param actorToken the actor token
	 */
	public TokenExchangeGrantRequest(ClientRegistration clientRegistration, OAuth2Token subjectToken,
			OAuth2Token actorToken) {
		super(AuthorizationGrantType.TOKEN_EXCHANGE, clientRegistration);
		Assert.isTrue(AuthorizationGrantType.TOKEN_EXCHANGE.equals(clientRegistration.getAuthorizationGrantType()),
				"clientRegistration.authorizationGrantType must be AuthorizationGrantType.TOKEN_EXCHANGE");
		Assert.notNull(subjectToken, "subjectToken cannot be null");
		this.subjectToken = subjectToken;
		this.actorToken = actorToken;
	}

	/**
	 * Returns the {@link OAuth2Token subject token}.
	 * @return the {@link OAuth2Token subject token}
	 */
	public OAuth2Token getSubjectToken() {
		return this.subjectToken;
	}

	/**
	 * Returns the {@link OAuth2Token actor token}.
	 * @return the {@link OAuth2Token actor token}
	 */
	public OAuth2Token getActorToken() {
		return this.actorToken;
	}

}
