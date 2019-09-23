/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.client.web.server;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.TestOAuth2AuthorizationCodeAuthenticationTokens;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.handler.DefaultWebFilterChain;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2AuthorizationCodeGrantWebFilterTests {
	private OAuth2AuthorizationCodeGrantWebFilter filter;
	@Mock
	private ReactiveAuthenticationManager authenticationManager;
	@Mock
	private ReactiveClientRegistrationRepository clientRegistrationRepository;
	@Mock
	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
	@Mock
	private ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

	@Before
	public void setup() {
		this.filter = new OAuth2AuthorizationCodeGrantWebFilter(
				this.authenticationManager, this.clientRegistrationRepository,
				this.authorizedClientRepository);
		when(this.authorizationRequestRepository.loadAuthorizationRequest(any())).thenReturn(Mono.empty());
		this.filter.setAuthorizationRequestRepository(this.authorizationRequestRepository);
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenIllegalArgumentException() {
		this.authenticationManager = null;
		assertThatCode(() -> new OAuth2AuthorizationCodeGrantWebFilter(
				this.authenticationManager, this.clientRegistrationRepository,
				this.authorizedClientRepository))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryNullThenIllegalArgumentException() {
		this.clientRegistrationRepository = null;
		assertThatCode(() -> new OAuth2AuthorizationCodeGrantWebFilter(
				this.authenticationManager, this.clientRegistrationRepository,
				this.authorizedClientRepository))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenAuthorizedClientRepositoryNullThenIllegalArgumentException() {
		this.authorizedClientRepository = null;
		assertThatCode(() -> new OAuth2AuthorizationCodeGrantWebFilter(
				this.authenticationManager, this.clientRegistrationRepository,
				this.authorizedClientRepository))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void filterWhenNotMatchThenAuthenticationManagerNotCalled() {
		MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("/"));
		DefaultWebFilterChain chain = new DefaultWebFilterChain(
				e -> e.getResponse().setComplete());

		this.filter.filter(exchange, chain).block();

		verifyZeroInteractions(this.authenticationManager);
	}

	@Test
	public void filterWhenMatchThenAuthorizedClientSaved() {
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
				.redirectUri("/authorize/registration-id")
				.build();
		OAuth2AuthorizationResponse authorizationResponse = TestOAuth2AuthorizationResponses.success()
				.redirectUri("/authorize/registration-id")
				.build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
		ClientRegistration registration = TestClientRegistrations.clientRegistration().build();
		Mono<Authentication> authentication = Mono.just(
				new OAuth2AuthorizationCodeAuthenticationToken(registration, authorizationExchange));
		OAuth2AuthorizationCodeAuthenticationToken authenticated = TestOAuth2AuthorizationCodeAuthenticationTokens
				.authenticated();

		when(this.authenticationManager.authenticate(any())).thenReturn(
				Mono.just(authenticated));
		when(this.authorizationRequestRepository.loadAuthorizationRequest(any()))
				.thenReturn(Mono.just(authorizationRequest));
		when(this.authorizedClientRepository.saveAuthorizedClient(any(), any(), any()))
				.thenReturn(Mono.empty());
		ServerAuthenticationConverter converter = e -> authentication;

		this.filter = new OAuth2AuthorizationCodeGrantWebFilter(
				this.authenticationManager, converter, this.authorizedClientRepository);
		this.filter.setAuthorizationRequestRepository(this.authorizationRequestRepository);

		MockServerHttpRequest request = MockServerHttpRequest
				.get("/authorize/registration-id")
				.queryParam(OAuth2ParameterNames.CODE, "code")
				.queryParam(OAuth2ParameterNames.STATE, "state")
				.build();
		MockServerWebExchange exchange = MockServerWebExchange.from(request);
		DefaultWebFilterChain chain = new DefaultWebFilterChain(
				e -> e.getResponse().setComplete());

		this.filter.filter(exchange, chain).block();

		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), any(AnonymousAuthenticationToken.class), any());
	}
}
