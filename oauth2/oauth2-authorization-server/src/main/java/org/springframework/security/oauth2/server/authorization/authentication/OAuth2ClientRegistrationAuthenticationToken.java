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

import java.io.Serial;
import java.util.Collections;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Dynamic Client
 * Registration Endpoint.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see AbstractAuthenticationToken
 * @see OAuth2ClientRegistration
 * @see OAuth2ClientRegistrationAuthenticationProvider
 */
public class OAuth2ClientRegistrationAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 7135429161909989115L;

	@Nullable
	private final Authentication principal;

	private final OAuth2ClientRegistration clientRegistration;

	/**
	 * Constructs an {@code OAuth2ClientRegistrationAuthenticationToken} using the
	 * provided parameters.
	 * @param principal the authenticated principal
	 * @param clientRegistration the client registration
	 */
	public OAuth2ClientRegistrationAuthenticationToken(@Nullable Authentication principal,
			OAuth2ClientRegistration clientRegistration) {
		super(Collections.emptyList());
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		this.principal = principal;
		this.clientRegistration = clientRegistration;
		if (principal != null) {
			setAuthenticated(principal.isAuthenticated());
		}
	}

	@Nullable
	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the client registration.
	 * @return the client registration
	 */
	public OAuth2ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

}
