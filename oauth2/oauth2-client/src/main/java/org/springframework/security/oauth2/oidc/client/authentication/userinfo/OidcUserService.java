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
package org.springframework.security.oauth2.oidc.client.authentication.userinfo;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.userinfo.NimbusUserInfoRetriever;
import org.springframework.security.oauth2.client.authentication.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.authentication.userinfo.UserInfoRetriever;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.oidc.client.authentication.OidcClientAuthenticationToken;
import org.springframework.security.oauth2.oidc.core.OidcScope;
import org.springframework.security.oauth2.oidc.core.UserInfo;
import org.springframework.security.oauth2.oidc.core.user.DefaultOidcUser;
import org.springframework.security.oauth2.oidc.core.user.OidcUserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Arrays;
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
	private final Set<String> userInfoScopes = new HashSet<>(
		Arrays.asList(OidcScope.PROFILE, OidcScope.EMAIL, OidcScope.ADDRESS, OidcScope.PHONE));

	@Override
	public OAuth2User loadUser(OAuth2ClientAuthenticationToken clientAuthentication) throws OAuth2AuthenticationException {
		OidcClientAuthenticationToken oidcClientAuthentication = (OidcClientAuthenticationToken)clientAuthentication;

		UserInfo userInfo = null;
		if (this.shouldRetrieveUserInfo(oidcClientAuthentication)) {
			Map<String, Object> userAttributes = this.userInfoRetriever.retrieve(oidcClientAuthentication);
			userInfo = new UserInfo(userAttributes);
		}

		GrantedAuthority authority = new OidcUserAuthority(oidcClientAuthentication.getIdToken(), userInfo);
		Set<GrantedAuthority> authorities = new HashSet<>();
		authorities.add(authority);

		return new DefaultOidcUser(authorities, oidcClientAuthentication.getIdToken(), userInfo);
	}

	public final void setUserInfoRetriever(UserInfoRetriever userInfoRetriever) {
		Assert.notNull(userInfoRetriever, "userInfoRetriever cannot be null");
		this.userInfoRetriever = userInfoRetriever;
	}

	private boolean shouldRetrieveUserInfo(OidcClientAuthenticationToken oidcClientAuthentication) {
		// Auto-disabled if UserInfo Endpoint URI is not provided
		if (StringUtils.isEmpty(oidcClientAuthentication.getClientRegistration().getProviderDetails()
			.getUserInfoEndpoint().getUri())) {

			return false;
		}

		// The Claims requested by the profile, email, address, and phone scope values
		// are returned from the UserInfo Endpoint (as described in Section 5.3.2),
		// when a response_type value is used that results in an Access Token being issued.
		// However, when no Access Token is issued, which is the case for the response_type=id_token,
		// the resulting Claims are returned in the ID Token.
		// The Authorization Code Grant Flow, which is response_type=code, results in an Access Token being issued.
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(
			oidcClientAuthentication.getClientRegistration().getAuthorizationGrantType())) {

			// Return true if there is at least one match between the authorized scope(s) and UserInfo scope(s)
			return oidcClientAuthentication.getAuthorizedScopes().stream().anyMatch(userInfoScopes::contains);
		}

		return false;
	}
}
