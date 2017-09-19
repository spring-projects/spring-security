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
package org.springframework.security.oauth2.client.token;

import org.springframework.security.oauth2.client.authentication.OAuth2UserAuthenticationToken;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.oidc.core.user.OidcUser;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

/**
 * A basic implementation of a {@link SecurityTokenRepository}
 * that stores {@link AccessToken}(s) <i>in-memory</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see SecurityTokenRepository
 * @see AccessToken
 */
public final class InMemoryAccessTokenRepository implements SecurityTokenRepository<AccessToken> {
	private final Map<String, AccessToken> accessTokens = new HashMap<>();

	@Override
	public AccessToken loadSecurityToken(OAuth2UserAuthenticationToken authentication) {
		Assert.notNull(authentication, "authentication cannot be null");
		return this.accessTokens.get(this.resolveAuthenticationKey(authentication));
	}

	@Override
	public void saveSecurityToken(AccessToken accessToken, OAuth2UserAuthenticationToken authentication) {
		Assert.notNull(accessToken, "accessToken cannot be null");
		Assert.notNull(authentication, "authentication cannot be null");
		this.accessTokens.put(this.resolveAuthenticationKey(authentication), accessToken);
	}

	@Override
	public void removeSecurityToken(OAuth2UserAuthenticationToken authentication) {
		Assert.notNull(authentication, "authentication cannot be null");
		this.accessTokens.remove(this.resolveAuthenticationKey(authentication));
	}

	private String resolveAuthenticationKey(OAuth2UserAuthenticationToken authentication) {
		String authenticationKey;

		OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
		if (OidcUser.class.isAssignableFrom(oauth2User.getClass())) {
			OidcUser oidcUser = (OidcUser)oauth2User;
			authenticationKey = oidcUser.getIssuer().toString() + "-" + oidcUser.getSubject();
		} else {
			authenticationKey = authentication.getClientAuthentication().getClientRegistration()
				.getProviderDetails().getUserInfoUri() + "-" +  oauth2User.getName();
		}

		return authenticationKey;
	}
}
