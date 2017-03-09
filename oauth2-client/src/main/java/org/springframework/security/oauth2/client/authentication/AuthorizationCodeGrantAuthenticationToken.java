/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.authentication;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantAuthenticationToken extends AuthorizationGrantAuthenticationToken {
	private final String authorizationCode;
	private final ClientRegistration clientRegistration;

	public AuthorizationCodeGrantAuthenticationToken(String authorizationCode, ClientRegistration clientRegistration) {
		super(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorityUtils.NO_AUTHORITIES);

		Assert.hasText(authorizationCode, "authorizationCode cannot be empty");
		this.authorizationCode = authorizationCode;

		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		this.clientRegistration = clientRegistration;

		this.setAuthenticated(false);
	}

	@Override
	public final Object getPrincipal() {
		return null;
	}

	@Override
	public final Object getCredentials() {
		return this.getAuthorizationCode();
	}

	public final String getAuthorizationCode() {
		return this.authorizationCode;
	}

	public final ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}
}