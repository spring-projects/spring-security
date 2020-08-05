/*
 * Copyright 2002-2018 the original author or authors.
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
import org.springframework.util.Assert;

/**
 * An OAuth 2.0 Client Credentials Grant request that holds the client's credentials in
 * {@link #getClientRegistration()}.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see ClientRegistration
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-1.3.4">Section 1.3.4 Client Credentials
 * Grant</a>
 */
public class OAuth2ClientCredentialsGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

	private final ClientRegistration clientRegistration;

	/**
	 * Constructs an {@code OAuth2ClientCredentialsGrantRequest} using the provided
	 * parameters.
	 * @param clientRegistration the client registration
	 */
	public OAuth2ClientCredentialsGrantRequest(ClientRegistration clientRegistration) {
		super(AuthorizationGrantType.CLIENT_CREDENTIALS);
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		Assert.isTrue(AuthorizationGrantType.CLIENT_CREDENTIALS.equals(clientRegistration.getAuthorizationGrantType()),
				"clientRegistration.authorizationGrantType must be AuthorizationGrantType.CLIENT_CREDENTIALS");
		this.clientRegistration = clientRegistration;
	}

	/**
	 * Returns the {@link ClientRegistration client registration}.
	 * @return the {@link ClientRegistration}
	 */
	public ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

}
