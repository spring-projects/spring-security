/*
 * Copyright 2002-2018 the original author or authors.
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

import java.util.Collection;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

import reactor.core.publisher.Mono;


/**
 * An implementation of an {@link org.springframework.security.authentication.AuthenticationProvider} for OAuth 2.0 Login,
 * which leverages the OAuth 2.0 Authorization Code Grant Flow.
 *
 * This {@link org.springframework.security.authentication.AuthenticationProvider} is responsible for authenticating
 * an Authorization Code credential with the Authorization Server's Token Endpoint
 * and if valid, exchanging it for an Access Token credential.
 * <p>
 * It will also obtain the user attributes of the End-User (Resource Owner)
 * from the UserInfo Endpoint using an {@link org.springframework.security.oauth2.client.userinfo.OAuth2UserService},
 * which will create a {@code Principal} in the form of an {@link OAuth2User}.
 * The {@code OAuth2User} is then associated to the {@link OAuth2LoginAuthenticationToken}
 * to complete the authentication.
 *
 * @author Rob Winch
 * @since 5.1
 * @see OAuth2LoginAuthenticationToken
 * @see org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient
 * @see org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService
 * @see OAuth2User
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token Response</a>
 */
public class OAuth2LoginReactiveAuthenticationManager implements
		ReactiveAuthenticationManager {
	private final ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	private final ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> userService;

	private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

	private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

	public OAuth2LoginReactiveAuthenticationManager(
			ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,
			ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> userService,
			ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		Assert.notNull(userService, "userService cannot be null");
		Assert.notNull(authorizedClientService, "authorizedClientService");
		this.accessTokenResponseClient = accessTokenResponseClient;
		this.userService = userService;
		this.authorizedClientService = authorizedClientService;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.defer(() -> {
			OAuth2LoginAuthenticationToken authorizationCodeAuthentication = (OAuth2LoginAuthenticationToken) authentication;

			// Section 3.1.2.1 Authentication Request - http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			// scope REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
			if (authorizationCodeAuthentication.getAuthorizationExchange()
					.getAuthorizationRequest().getScopes().contains("openid")) {
				// This is an OpenID Connect Authentication Request so return null
				// and let OidcAuthorizationCodeReactiveAuthenticationManager handle it instead once one is created
				// FIXME: Once we create OidcAuthorizationCodeReactiveAuthenticationManager uncomment below
//				return Mono.empty();
			}

			OAuth2AuthorizationExchangeValidator.validate(authorizationCodeAuthentication.getAuthorizationExchange());

			OAuth2AuthorizationCodeGrantRequest authzRequest = new OAuth2AuthorizationCodeGrantRequest(
					authorizationCodeAuthentication.getClientRegistration(),
					authorizationCodeAuthentication.getAuthorizationExchange());

			return this.accessTokenResponseClient.getTokenResponse(authzRequest)
					.flatMap(accessTokenResponse -> authenticationResult(authorizationCodeAuthentication, accessTokenResponse));
		});
	}

	private Mono<OAuth2AuthenticationToken> authenticationResult(OAuth2LoginAuthenticationToken authorizationCodeAuthentication, OAuth2AccessTokenResponse accessTokenResponse) {
		OAuth2AccessToken accessToken = accessTokenResponse.getAccessToken();
		OAuth2UserRequest userRequest = new OAuth2UserRequest(authorizationCodeAuthentication.getClientRegistration(), accessToken);
		return this.userService.loadUser(userRequest)
				.flatMap(oauth2User -> {
					Collection<? extends GrantedAuthority> mappedAuthorities =
							this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());

					OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(
							authorizationCodeAuthentication.getClientRegistration(),
							authorizationCodeAuthentication.getAuthorizationExchange(),
							oauth2User,
							mappedAuthorities,
							accessToken,
							accessTokenResponse.getRefreshToken());
					OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
							authenticationResult.getClientRegistration(),
							authenticationResult.getName(),
							authenticationResult.getAccessToken(),
							authenticationResult.getRefreshToken());
					OAuth2AuthenticationToken result =  new OAuth2AuthenticationToken(
							authenticationResult.getPrincipal(),
							authenticationResult.getAuthorities(),
							authenticationResult.getClientRegistration().getRegistrationId());
					return this.authorizedClientService.saveAuthorizedClient(authorizedClient, authenticationResult)
							.thenReturn(result);
				});
	}
}
