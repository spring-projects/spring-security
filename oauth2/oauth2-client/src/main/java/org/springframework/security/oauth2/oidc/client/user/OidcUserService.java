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
package org.springframework.security.oauth2.oidc.client.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.client.user.UserInfoRetriever;
import org.springframework.security.oauth2.client.user.nimbus.NimbusUserInfoRetriever;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.oidc.client.authentication.OidcClientAuthenticationToken;
import org.springframework.security.oauth2.oidc.core.UserInfo;
import org.springframework.security.oauth2.oidc.core.user.DefaultOidcUser;
import org.springframework.security.oauth2.oidc.core.user.OidcUserAuthority;
import org.springframework.util.Assert;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * An implementation of an {@link OAuth2UserService} that supports <i>OpenID Connect 1.0 Provider's</i>.
 * <p>
 * This implementation uses a {@link UserInfoRetriever} to obtain the user attributes
 * of the <i>End-User</i> (resource owner) from the <i>UserInfo Endpoint</i>
 * and constructs a {@link UserInfo} instance.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2UserService
 * @see OidcClientAuthenticationToken
 * @see DefaultOidcUser
 * @see UserInfo
 * @see UserInfoRetriever
 */
public class OidcUserService implements OAuth2UserService {
	private UserInfoRetriever userInfoRetriever = new NimbusUserInfoRetriever();

	@Override
	public OAuth2User loadUser(OAuth2ClientAuthenticationToken clientAuthentication) throws OAuth2AuthenticationException {
		if (!OidcClientAuthenticationToken.class.isAssignableFrom(clientAuthentication.getClass())) {
			return null;
		}
		OidcClientAuthenticationToken oidcClientAuthentication = (OidcClientAuthenticationToken)clientAuthentication;

		Map<String, Object> userAttributes = this.getUserInfoRetriever().retrieve(oidcClientAuthentication);
		UserInfo userInfo = new UserInfo(userAttributes);

		GrantedAuthority authority = new OidcUserAuthority(oidcClientAuthentication.getIdToken(), userInfo);
		Set<GrantedAuthority> authorities = new HashSet<>();
		authorities.add(authority);

		return new DefaultOidcUser(authorities, oidcClientAuthentication.getIdToken(), userInfo);
	}

	protected UserInfoRetriever getUserInfoRetriever() {
		return this.userInfoRetriever;
	}

	public final void setUserInfoRetriever(UserInfoRetriever userInfoRetriever) {
		Assert.notNull(userInfoRetriever, "userInfoRetriever cannot be null");
		this.userInfoRetriever = userInfoRetriever;
	}
}
