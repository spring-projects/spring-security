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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.token.SecurityTokenRepository;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.oidc.client.authentication.OidcClientAuthenticationToken;
import org.springframework.security.oauth2.oidc.client.authentication.OidcUserAuthenticationToken;
import org.springframework.security.oauth2.oidc.core.user.OidcUser;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * An implementation of an {@link AuthenticationProvider} that is responsible for authenticating
 * an <i>authorization code</i> credential with the authorization server's <i>Token Endpoint</i>
 * and if valid, exchanging it for an <i>access token</i> credential and optionally an
 * <i>id token</i> credential (for OpenID Connect Authorization Code Flow).
 * Additionally, it will also obtain the end-user's (resource owner) attributes from the <i>UserInfo Endpoint</i>
 * (using the <i>access token</i>) and create a <code>Principal</code> in the form of an {@link OAuth2User}
 * associating it with the returned {@link OAuth2UserAuthenticationToken}.
 *
 * <p>
 * The {@link AuthorizationCodeAuthenticationProvider} uses an {@link AuthorizationGrantAuthenticator}
 * to authenticate the {@link AuthorizationCodeAuthenticationToken#getAuthorizationCode()} and ultimately
 * return an <i>&quot;Authorized Client&quot;</i> as an {@link OAuth2ClientAuthenticationToken}.
 *
 * <p>
 * It will then call {@link OAuth2UserService#loadUser(OAuth2ClientAuthenticationToken)}
 * to obtain the end-user's (resource owner) attributes in the form of an {@link OAuth2User}.
 *
 * <p>
 * Finally, it will create an {@link OAuth2UserAuthenticationToken}, associating the {@link OAuth2User}
 * and {@link OAuth2ClientAuthenticationToken} and return it to the {@link AuthenticationManager},
 * at which point the {@link OAuth2UserAuthenticationToken} is considered <i>&quot;authenticated&quot;</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationCodeAuthenticationToken
 * @see OAuth2ClientAuthenticationToken
 * @see OidcClientAuthenticationToken
 * @see OAuth2UserAuthenticationToken
 * @see OidcUserAuthenticationToken
 * @see AuthorizationGrantAuthenticator
 * @see OAuth2UserService
 * @see OAuth2User
 * @see OidcUser
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">Section 3.1 OpenID Connect Authorization Code Flow</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token Response</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">Section 3.1.3.3 OpenID Connect Token Response</a>
 */
public class AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
	private final AuthorizationGrantAuthenticator<AuthorizationCodeAuthenticationToken> authorizationCodeAuthenticator;
	private final SecurityTokenRepository<AccessToken> accessTokenRepository;
	private final OAuth2UserService userService;
	private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

	public AuthorizationCodeAuthenticationProvider(
			AuthorizationGrantAuthenticator<AuthorizationCodeAuthenticationToken> authorizationCodeAuthenticator,
			SecurityTokenRepository<AccessToken> accessTokenRepository,
			OAuth2UserService userService) {

		Assert.notNull(authorizationCodeAuthenticator, "authorizationCodeAuthenticator cannot be null");
		Assert.notNull(accessTokenRepository, "accessTokenRepository cannot be null");
		Assert.notNull(userService, "userService cannot be null");
		this.authorizationCodeAuthenticator = authorizationCodeAuthenticator;
		this.accessTokenRepository = accessTokenRepository;
		this.userService = userService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
				(AuthorizationCodeAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken oauth2ClientAuthentication =
			this.authorizationCodeAuthenticator.authenticate(authorizationCodeAuthentication);

		this.accessTokenRepository.saveSecurityToken(
			oauth2ClientAuthentication.getAccessToken(),
			oauth2ClientAuthentication.getClientRegistration());

		OAuth2User oauth2User = this.userService.loadUser(oauth2ClientAuthentication);

		Collection<? extends GrantedAuthority> mappedAuthorities =
				this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());

		OAuth2UserAuthenticationToken oauth2UserAuthentication;
		if (OidcUser.class.isAssignableFrom(oauth2User.getClass())) {
			oauth2UserAuthentication = new OidcUserAuthenticationToken(
				(OidcUser)oauth2User, mappedAuthorities, (OidcClientAuthenticationToken)oauth2ClientAuthentication);
		} else {
			oauth2UserAuthentication = new OAuth2UserAuthenticationToken(
				oauth2User, mappedAuthorities, oauth2ClientAuthentication);
		}
		oauth2UserAuthentication.setDetails(oauth2ClientAuthentication.getDetails());

		return oauth2UserAuthentication;
	}

	public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
