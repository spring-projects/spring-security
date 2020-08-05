/*
 * Copyright 2002-2020 the original author or authors.
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

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.authentication.TestOAuth2AuthorizationCodeAuthenticationTokens;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.handler.DefaultWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests.request;

/**
 * @author Rob Winch
 * @author Parikshit Dutta
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
		this.filter = new OAuth2AuthorizationCodeGrantWebFilter(this.authenticationManager,
				this.clientRegistrationRepository, this.authorizedClientRepository);
		this.filter.setAuthorizationRequestRepository(this.authorizationRequestRepository);
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenIllegalArgumentException() {
		this.authenticationManager = null;
		assertThatCode(() -> new OAuth2AuthorizationCodeGrantWebFilter(this.authenticationManager,
				this.clientRegistrationRepository, this.authorizedClientRepository))
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryNullThenIllegalArgumentException() {
		this.clientRegistrationRepository = null;
		assertThatCode(() -> new OAuth2AuthorizationCodeGrantWebFilter(this.authenticationManager,
				this.clientRegistrationRepository, this.authorizedClientRepository))
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenAuthorizedClientRepositoryNullThenIllegalArgumentException() {
		this.authorizedClientRepository = null;
		assertThatCode(() -> new OAuth2AuthorizationCodeGrantWebFilter(this.authenticationManager,
				this.clientRegistrationRepository, this.authorizedClientRepository))
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setRequestCacheWhenRequestCacheIsNullThenThrowIllegalArgumentException() {
		assertThatCode(() -> this.filter.setRequestCache(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void filterWhenNotMatchThenAuthenticationManagerNotCalled() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		DefaultWebFilterChain chain = new DefaultWebFilterChain(e -> e.getResponse().setComplete(),
				Collections.emptyList());

		this.filter.filter(exchange, chain).block();

		verifyNoInteractions(this.authenticationManager);
	}

	@Test
	public void filterWhenMatchThenAuthorizedClientSaved() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(clientRegistration));

		MockServerHttpRequest authorizationRequest = createAuthorizationRequest("/authorization/callback");
		OAuth2AuthorizationRequest oauth2AuthorizationRequest = createOAuth2AuthorizationRequest(authorizationRequest,
				clientRegistration);
		when(this.authorizationRequestRepository.loadAuthorizationRequest(any()))
				.thenReturn(Mono.just(oauth2AuthorizationRequest));
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any()))
				.thenReturn(Mono.just(oauth2AuthorizationRequest));

		when(this.authorizedClientRepository.saveAuthorizedClient(any(), any(), any())).thenReturn(Mono.empty());
		when(this.authenticationManager.authenticate(any()))
				.thenReturn(Mono.just(TestOAuth2AuthorizationCodeAuthenticationTokens.authenticated()));

		MockServerHttpRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockServerWebExchange exchange = MockServerWebExchange.from(authorizationResponse);
		DefaultWebFilterChain chain = new DefaultWebFilterChain(e -> e.getResponse().setComplete(),
				Collections.emptyList());

		this.filter.filter(exchange, chain).block();

		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), any(AnonymousAuthenticationToken.class),
				any());
	}

	// gh-7966
	@Test
	public void filterWhenAuthorizationRequestRedirectUriParametersMatchThenProcessed() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(clientRegistration));
		when(this.authorizedClientRepository.saveAuthorizedClient(any(), any(), any())).thenReturn(Mono.empty());
		when(this.authenticationManager.authenticate(any()))
				.thenReturn(Mono.just(TestOAuth2AuthorizationCodeAuthenticationTokens.authenticated()));

		// 1) redirect_uri with query parameters
		Map<String, String> parameters = new LinkedHashMap<>();
		parameters.put("param1", "value1");
		parameters.put("param2", "value2");
		MockServerHttpRequest authorizationRequest = createAuthorizationRequest("/authorization/callback", parameters);
		OAuth2AuthorizationRequest oauth2AuthorizationRequest = createOAuth2AuthorizationRequest(authorizationRequest,
				clientRegistration);
		when(this.authorizationRequestRepository.loadAuthorizationRequest(any()))
				.thenReturn(Mono.just(oauth2AuthorizationRequest));
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any()))
				.thenReturn(Mono.just(oauth2AuthorizationRequest));

		MockServerHttpRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockServerWebExchange exchange = MockServerWebExchange.from(authorizationResponse);
		DefaultWebFilterChain chain = new DefaultWebFilterChain(e -> e.getResponse().setComplete(),
				Collections.emptyList());

		this.filter.filter(exchange, chain).block();
		verify(this.authenticationManager, times(1)).authenticate(any());

		// 2) redirect_uri with query parameters AND authorization response additional
		// parameters
		Map<String, String> additionalParameters = new LinkedHashMap<>();
		additionalParameters.put("auth-param1", "value1");
		additionalParameters.put("auth-param2", "value2");
		authorizationResponse = createAuthorizationResponse(authorizationRequest, additionalParameters);
		exchange = MockServerWebExchange.from(authorizationResponse);

		this.filter.filter(exchange, chain).block();
		verify(this.authenticationManager, times(2)).authenticate(any());
	}

	// gh-7966
	@Test
	public void filterWhenAuthorizationRequestRedirectUriParametersNotMatchThenNotProcessed() {
		String requestUri = "/authorization/callback";
		Map<String, String> parameters = new LinkedHashMap<>();
		parameters.put("param1", "value1");
		parameters.put("param2", "value2");
		MockServerHttpRequest authorizationRequest = createAuthorizationRequest(requestUri, parameters);
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		OAuth2AuthorizationRequest oauth2AuthorizationRequest = createOAuth2AuthorizationRequest(authorizationRequest,
				clientRegistration);
		when(this.authorizationRequestRepository.loadAuthorizationRequest(any()))
				.thenReturn(Mono.just(oauth2AuthorizationRequest));

		// 1) Parameter value
		Map<String, String> parametersNotMatch = new LinkedHashMap<>(parameters);
		parametersNotMatch.put("param2", "value8");
		MockServerHttpRequest authorizationResponse = createAuthorizationResponse(
				createAuthorizationRequest(requestUri, parametersNotMatch));
		MockServerWebExchange exchange = MockServerWebExchange.from(authorizationResponse);
		DefaultWebFilterChain chain = new DefaultWebFilterChain(e -> e.getResponse().setComplete(),
				Collections.emptyList());

		this.filter.filter(exchange, chain).block();
		verifyNoInteractions(this.authenticationManager);

		// 2) Parameter order
		parametersNotMatch = new LinkedHashMap<>();
		parametersNotMatch.put("param2", "value2");
		parametersNotMatch.put("param1", "value1");
		authorizationResponse = createAuthorizationResponse(createAuthorizationRequest(requestUri, parametersNotMatch));
		exchange = MockServerWebExchange.from(authorizationResponse);

		this.filter.filter(exchange, chain).block();
		verifyNoInteractions(this.authenticationManager);

		// 3) Parameter missing
		parametersNotMatch = new LinkedHashMap<>(parameters);
		parametersNotMatch.remove("param2");
		authorizationResponse = createAuthorizationResponse(createAuthorizationRequest(requestUri, parametersNotMatch));
		exchange = MockServerWebExchange.from(authorizationResponse);

		this.filter.filter(exchange, chain).block();
		verifyNoInteractions(this.authenticationManager);
	}

	@Test
	public void filterWhenAuthorizationSucceedsAndRequestCacheConfiguredThenRequestCacheUsed() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(clientRegistration));
		when(this.authorizedClientRepository.saveAuthorizedClient(any(), any(), any())).thenReturn(Mono.empty());
		when(this.authenticationManager.authenticate(any()))
				.thenReturn(Mono.just(TestOAuth2AuthorizationCodeAuthenticationTokens.authenticated()));

		MockServerHttpRequest authorizationRequest = createAuthorizationRequest("/authorization/callback");
		OAuth2AuthorizationRequest oauth2AuthorizationRequest = createOAuth2AuthorizationRequest(authorizationRequest,
				clientRegistration);
		when(this.authorizationRequestRepository.loadAuthorizationRequest(any()))
				.thenReturn(Mono.just(oauth2AuthorizationRequest));
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any()))
				.thenReturn(Mono.just(oauth2AuthorizationRequest));

		MockServerHttpRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockServerWebExchange exchange = MockServerWebExchange.from(authorizationResponse);
		DefaultWebFilterChain chain = new DefaultWebFilterChain(e -> e.getResponse().setComplete(),
				Collections.emptyList());

		ServerRequestCache requestCache = mock(ServerRequestCache.class);
		when(requestCache.getRedirectUri(any(ServerWebExchange.class)))
				.thenReturn(Mono.just(URI.create("/saved-request")));

		this.filter.setRequestCache(requestCache);

		this.filter.filter(exchange, chain).block();

		verify(requestCache).getRedirectUri(exchange);
		assertThat(exchange.getResponse().getHeaders().getLocation().toString()).isEqualTo("/saved-request");
	}

	// gh-8609
	@Test
	public void filterWhenAuthenticationConverterThrowsOAuth2AuthorizationExceptionThenMappedToOAuth2AuthenticationException() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.empty());

		MockServerHttpRequest authorizationRequest = createAuthorizationRequest("/authorization/callback");
		OAuth2AuthorizationRequest oauth2AuthorizationRequest = createOAuth2AuthorizationRequest(authorizationRequest,
				clientRegistration);
		when(this.authorizationRequestRepository.loadAuthorizationRequest(any()))
				.thenReturn(Mono.just(oauth2AuthorizationRequest));
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any()))
				.thenReturn(Mono.just(oauth2AuthorizationRequest));

		MockServerHttpRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockServerWebExchange exchange = MockServerWebExchange.from(authorizationResponse);
		DefaultWebFilterChain chain = new DefaultWebFilterChain(e -> e.getResponse().setComplete(),
				Collections.emptyList());

		assertThatThrownBy(() -> this.filter.filter(exchange, chain).block())
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo("client_registration_not_found");
		verifyNoInteractions(this.authenticationManager);
	}

	// gh-8609
	@Test
	public void filterWhenAuthenticationManagerThrowsOAuth2AuthorizationExceptionThenMappedToOAuth2AuthenticationException() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(clientRegistration));

		MockServerHttpRequest authorizationRequest = createAuthorizationRequest("/authorization/callback");
		OAuth2AuthorizationRequest oauth2AuthorizationRequest = createOAuth2AuthorizationRequest(authorizationRequest,
				clientRegistration);
		when(this.authorizationRequestRepository.loadAuthorizationRequest(any()))
				.thenReturn(Mono.just(oauth2AuthorizationRequest));
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any()))
				.thenReturn(Mono.just(oauth2AuthorizationRequest));

		when(this.authenticationManager.authenticate(any()))
				.thenReturn(Mono.error(new OAuth2AuthorizationException(new OAuth2Error("authorization_error"))));

		MockServerHttpRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockServerWebExchange exchange = MockServerWebExchange.from(authorizationResponse);
		DefaultWebFilterChain chain = new DefaultWebFilterChain(e -> e.getResponse().setComplete(),
				Collections.emptyList());

		assertThatThrownBy(() -> this.filter.filter(exchange, chain).block())
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo("authorization_error");
	}

	private static OAuth2AuthorizationRequest createOAuth2AuthorizationRequest(
			MockServerHttpRequest authorizationRequest, ClientRegistration registration) {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, registration.getRegistrationId());
		return request().attributes(attributes).redirectUri(authorizationRequest.getURI().toString()).build();
	}

	private static MockServerHttpRequest createAuthorizationRequest(String requestUri) {
		return createAuthorizationRequest(requestUri, new LinkedHashMap<>());
	}

	private static MockServerHttpRequest createAuthorizationRequest(String requestUri, Map<String, String> parameters) {
		MockServerHttpRequest.BaseBuilder<?> builder = MockServerHttpRequest.get(requestUri);
		if (!CollectionUtils.isEmpty(parameters)) {
			parameters.forEach(builder::queryParam);
		}
		return builder.build();
	}

	private static MockServerHttpRequest createAuthorizationResponse(MockServerHttpRequest authorizationRequest) {
		return createAuthorizationResponse(authorizationRequest, new LinkedHashMap<>());
	}

	private static MockServerHttpRequest createAuthorizationResponse(MockServerHttpRequest authorizationRequest,
			Map<String, String> additionalParameters) {
		MockServerHttpRequest.BaseBuilder<?> builder = MockServerHttpRequest
				.get(authorizationRequest.getURI().toString());
		builder.queryParam(OAuth2ParameterNames.CODE, "code");
		builder.queryParam(OAuth2ParameterNames.STATE, "state");
		additionalParameters.forEach(builder::queryParam);
		builder.cookies(authorizationRequest.getCookies());
		return builder.build();
	}

}
