/*
 * Copyright 2002-2021 the original author or authors.
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
 * An OAuth 2.0 Resource Owner Password Credentials Grant request that holds the resource
 * owner's credentials.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-1.3.3">Section 1.3.3 Resource Owner
 * Password Credentials</a>
 */
public class OAuth2PasswordGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

	private final String username;

	private final String password;

	/**
	 * Constructs an {@code OAuth2PasswordGrantRequest} using the provided parameters.
	 * @param clientRegistration the client registration
	 * @param username the resource owner's username
	 * @param password the resource owner's password
	 */
	public OAuth2PasswordGrantRequest(ClientRegistration clientRegistration, String username, String password) {
		super(AuthorizationGrantType.PASSWORD, clientRegistration);
		Assert.isTrue(AuthorizationGrantType.PASSWORD.equals(clientRegistration.getAuthorizationGrantType()),
				"clientRegistration.authorizationGrantType must be AuthorizationGrantType.PASSWORD");
		Assert.hasText(username, "username cannot be empty");
		Assert.hasText(password, "password cannot be empty");
		this.username = username;
		this.password = password;
	}

	/**
	 * Returns the resource owner's username.
	 * @return the resource owner's username
	 */
	public String getUsername() {
		return this.username;
	}

	/**
	 * Returns the resource owner's password.
	 * @return the resource owner's password
	 */
	public String getPassword() {
		return this.password;
	}

}
