/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.client.web.server.authentication;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.handler.DefaultWebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2LoginAuthenticationWebFilterTests {

	@Mock
	private ReactiveAuthenticationManager authenticationManager;

	@Mock
	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	private OAuth2LoginAuthenticationWebFilter filter;

	private WebFilterExchange webFilterExchange;

	private ClientRegistration.Builder registration = TestClientRegistrations.clientRegistration();

	private OAuth2AuthorizationResponse.Builder authorizationResponseBldr = OAuth2AuthorizationResponse.success("code")
			.state("state");

	@Before
	public void setup() {
		this.filter = new OAuth2LoginAuthenticationWebFilter(this.authenticationManager,
				this.authorizedClientRepository);
		this.webFilterExchange = new WebFilterExchange(MockServerWebExchange.from(MockServerHttpRequest.get("/")),
				new DefaultWebFilterChain(exchange -> exchange.getResponse().setComplete()));
		when(this.authorizedClientRepository.saveAuthorizedClient(any(), any(), any())).thenReturn(Mono.empty());
	}

	@Test
	public void onAuthenticationSuccessWhenOAuth2LoginAuthenticationTokenThenSavesAuthorizedClient() {
		this.filter.onAuthenticationSuccess(loginToken(), this.webFilterExchange).block();

		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), any(), any());
	}

	private OAuth2LoginAuthenticationToken loginToken() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
				Instant.now(), Instant.now().plus(Duration.ofDays(1)), Collections.singleton("user"));
		DefaultOAuth2User user = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"),
				Collections.singletonMap("user", "rob"), "user");
		ClientRegistration clientRegistration = this.registration.build();
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode().state("state")
				.clientId(clientRegistration.getClientId())
				.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
				.redirectUri(clientRegistration.getRedirectUri()).scopes(clientRegistration.getScopes()).build();
		OAuth2AuthorizationResponse authorizationResponse = this.authorizationResponseBldr
				.redirectUri(clientRegistration.getRedirectUri()).build();
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(authorizationRequest,
				authorizationResponse);
		return new OAuth2LoginAuthenticationToken(clientRegistration, authorizationExchange, user,
				user.getAuthorities(), accessToken);
	}

}
