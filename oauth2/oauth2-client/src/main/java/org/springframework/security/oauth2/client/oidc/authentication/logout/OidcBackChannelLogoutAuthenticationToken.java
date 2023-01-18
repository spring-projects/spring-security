/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.authentication.logout;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

public class OidcBackChannelLogoutAuthenticationToken extends AbstractAuthenticationToken {

	private final String logoutToken;

	private final ClientRegistration clientRegistration;

	public OidcBackChannelLogoutAuthenticationToken(String logoutToken, ClientRegistration clientRegistration) {
		super(AuthorityUtils.NO_AUTHORITIES);
		this.logoutToken = logoutToken;
		this.clientRegistration = clientRegistration;
	}

	@Override
	public String getCredentials() {
		return this.logoutToken;
	}

	@Override
	public String getPrincipal() {
		return this.logoutToken;
	}

	public String getLogoutToken() {
		return this.logoutToken;
	}

	public ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

}
