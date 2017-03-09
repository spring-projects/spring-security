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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.userdetails.UserInfoUserDetailsService;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.RefreshToken;
import org.springframework.security.oauth2.core.protocol.TokenResponseAttributes;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantAuthenticationProvider implements AuthenticationProvider {
	private final AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> authorizationCodeGrantTokenExchanger;
	private final UserInfoUserDetailsService userInfoUserDetailsService;
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	public AuthorizationCodeGrantAuthenticationProvider(
			AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> authorizationCodeGrantTokenExchanger,
			UserInfoUserDetailsService userInfoUserDetailsService) {

		Assert.notNull(authorizationCodeGrantTokenExchanger, "authorizationCodeGrantTokenExchanger cannot be null");
		this.authorizationCodeGrantTokenExchanger = authorizationCodeGrantTokenExchanger;

		Assert.notNull(userInfoUserDetailsService, "userInfoUserDetailsService cannot be null");
		this.userInfoUserDetailsService = userInfoUserDetailsService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		AuthorizationCodeGrantAuthenticationToken authorizationCodeGrantAuthentication =
				(AuthorizationCodeGrantAuthenticationToken) authentication;

		TokenResponseAttributes tokenResponse =
				this.authorizationCodeGrantTokenExchanger.exchange(authorizationCodeGrantAuthentication);

		AccessToken accessToken = new AccessToken(tokenResponse.getAccessTokenType(),
				tokenResponse.getAccessToken(), tokenResponse.getExpiresIn(), tokenResponse.getScopes());
		RefreshToken refreshToken = null;
		if (tokenResponse.getRefreshToken() != null) {
			refreshToken = new RefreshToken(tokenResponse.getRefreshToken());
		}
		OAuth2AuthenticationToken accessTokenAuthentication = new OAuth2AuthenticationToken(
				authorizationCodeGrantAuthentication.getClientRegistration(), accessToken, refreshToken);
		accessTokenAuthentication.setDetails(authorizationCodeGrantAuthentication.getDetails());

		UserDetails userDetails = this.userInfoUserDetailsService.loadUserDetails(accessTokenAuthentication);

		Collection<? extends GrantedAuthority> authorities =
				this.authoritiesMapper.mapAuthorities(userDetails.getAuthorities());

		OAuth2AuthenticationToken authenticationResult = new OAuth2AuthenticationToken(userDetails, authorities,
				accessTokenAuthentication.getClientRegistration(), accessTokenAuthentication.getAccessToken(),
				accessTokenAuthentication.getRefreshToken());
		authenticationResult.setDetails(accessTokenAuthentication.getDetails());

		return authenticationResult;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return AuthorizationCodeGrantAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}
}