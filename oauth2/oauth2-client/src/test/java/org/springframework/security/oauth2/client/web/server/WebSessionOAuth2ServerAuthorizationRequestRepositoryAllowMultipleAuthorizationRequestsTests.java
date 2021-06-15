/*
 * Copyright 2002-2021 the original author or authors.
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

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.adapter.DefaultServerWebExchange;
import org.springframework.web.server.i18n.AcceptHeaderLocaleContextResolver;
import org.springframework.web.server.session.WebSessionManager;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link WebSessionOAuth2ServerAuthorizationRequestRepository} when
 * {@link WebSessionOAuth2ServerAuthorizationRequestRepository#setAllowMultipleAuthorizationRequests(boolean)}
 * is enabled.
 *
 * @author Steve Riesenberg
 */

public class WebSessionOAuth2ServerAuthorizationRequestRepositoryAllowMultipleAuthorizationRequestsTests
		extends WebSessionOAuth2ServerAuthorizationRequestRepositoryTests {

	@Before
	public void setup() {
		this.repository = new WebSessionOAuth2ServerAuthorizationRequestRepository();
		this.repository.setAllowMultipleAuthorizationRequests(true);
	}

	@Test
	public void loadAuthorizationRequestWhenMultipleSavedThenAuthorizationRequest() {
		String oldState = "state0";
		// @formatter:off
		MockServerHttpRequest oldRequest = MockServerHttpRequest.get("/")
				.queryParam(OAuth2ParameterNames.STATE, oldState)
				.build();
		OAuth2AuthorizationRequest oldAuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/oauth2/authorize")
				.clientId("client-id")
				.redirectUri("http://localhost/client-1")
				.state(oldState)
				.build();
		// @formatter:on
		WebSessionManager sessionManager = (e) -> this.exchange.getSession();
		this.exchange = new DefaultServerWebExchange(this.exchange.getRequest(), new MockServerHttpResponse(),
				sessionManager, ServerCodecConfigurer.create(), new AcceptHeaderLocaleContextResolver());
		ServerWebExchange oldExchange = new DefaultServerWebExchange(oldRequest, new MockServerHttpResponse(),
				sessionManager, ServerCodecConfigurer.create(), new AcceptHeaderLocaleContextResolver());
		// @formatter:off
		Mono<OAuth2AuthorizationRequest> saveAndSaveAndLoad = this.repository
				.saveAuthorizationRequest(oldAuthorizationRequest, oldExchange)
				.then(this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange))
				.then(this.repository.loadAuthorizationRequest(oldExchange));
		StepVerifier.create(saveAndSaveAndLoad)
				.expectNext(oldAuthorizationRequest)
				.verifyComplete();
		StepVerifier.create(this.repository.loadAuthorizationRequest(this.exchange))
				.expectNext(this.authorizationRequest)
				.verifyComplete();
		// @formatter:on
	}

	// gh-5145
	@Test
	public void loadAuthorizationRequestWhenSavedWithAllowMultipleAuthorizationRequestsThenReturnOldAuthorizationRequest() {
		// save 2 requests with legacy (allowMultipleAuthorizationRequests=true) and load
		// with new
		WebSessionOAuth2ServerAuthorizationRequestRepository legacy = new WebSessionOAuth2ServerAuthorizationRequestRepository();
		legacy.setAllowMultipleAuthorizationRequests(true);
		// @formatter:off
		String state1 = "state-1122";
		OAuth2AuthorizationRequest authorizationRequest1 = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/oauth2/authorize")
				.clientId("client-id")
				.redirectUri("http://localhost/client-1")
				.state(state1)
				.build();
		StepVerifier.create(legacy.saveAuthorizationRequest(authorizationRequest1, this.exchange))
				.verifyComplete();
		String state2 = "state-3344";
		OAuth2AuthorizationRequest authorizationRequest2 = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/oauth2/authorize")
				.clientId("client-id")
				.redirectUri("http://localhost/client-1")
				.state(state2)
				.build();
		StepVerifier.create(legacy.saveAuthorizationRequest(authorizationRequest2, this.exchange))
				.verifyComplete();
		ServerHttpRequest newRequest = MockServerHttpRequest.get("/")
				.queryParam(OAuth2ParameterNames.STATE, state1)
				.build();
		ServerWebExchange newExchange = this.exchange.mutate()
				.request(newRequest)
				.build();
		StepVerifier.create(this.repository.loadAuthorizationRequest(newExchange))
				.expectNext(authorizationRequest1)
				.verifyComplete();
		// @formatter:on
	}

	// gh-5145
	@Test
	public void saveAuthorizationRequestWhenSavedWithAllowMultipleAuthorizationRequestsThenLoadNewAuthorizationRequest() {
		// save 2 requests with legacy (allowMultipleAuthorizationRequests=true), save
		// with new, and load with new
		WebSessionOAuth2ServerAuthorizationRequestRepository legacy = new WebSessionOAuth2ServerAuthorizationRequestRepository();
		legacy.setAllowMultipleAuthorizationRequests(true);
		// @formatter:off
		String state1 = "state-1122";
		OAuth2AuthorizationRequest authorizationRequest1 = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/oauth2/authorize")
				.clientId("client-id")
				.redirectUri("http://localhost/client-1")
				.state(state1)
				.build();
		StepVerifier.create(legacy.saveAuthorizationRequest(authorizationRequest1, this.exchange))
				.verifyComplete();
		String state2 = "state-3344";
		OAuth2AuthorizationRequest authorizationRequest2 = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/oauth2/authorize")
				.clientId("client-id")
				.redirectUri("http://localhost/client-1")
				.state(state2)
				.build();
		StepVerifier.create(legacy.saveAuthorizationRequest(authorizationRequest2, this.exchange))
				.verifyComplete();
		String state3 = "state-5566";
		OAuth2AuthorizationRequest authorizationRequest3 = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/oauth2/authorize")
				.clientId("client-id")
				.redirectUri("http://localhost/client-1")
				.state(state3)
				.build();
		ServerHttpRequest newRequest = MockServerHttpRequest.get("/")
				.queryParam(OAuth2ParameterNames.STATE, state3)
				.build();
		ServerWebExchange newExchange = this.exchange.mutate()
				.request(newRequest)
				.build();
		Mono<OAuth2AuthorizationRequest> saveAndLoad = this.repository
				.saveAuthorizationRequest(authorizationRequest3, this.exchange)
				.then(this.repository.loadAuthorizationRequest(newExchange));
		StepVerifier.create(saveAndLoad)
				.expectNext(authorizationRequest3)
				.verifyComplete();
		// @formatter:on
	}

	@Test
	public void removeAuthorizationRequestWhenMultipleThenOnlyOneRemoved() {
		String oldState = "state0";
		// @formatter:off
		MockServerHttpRequest oldRequest = MockServerHttpRequest.get("/")
				.queryParam(OAuth2ParameterNames.STATE, oldState)
				.build();
		OAuth2AuthorizationRequest oldAuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/oauth2/authorize")
				.clientId("client-id")
				.redirectUri("http://localhost/client-1")
				.state(oldState)
				.build();
		// @formatter:on
		WebSessionManager sessionManager = (e) -> this.exchange.getSession();
		this.exchange = new DefaultServerWebExchange(this.exchange.getRequest(), new MockServerHttpResponse(),
				sessionManager, ServerCodecConfigurer.create(), new AcceptHeaderLocaleContextResolver());
		ServerWebExchange oldExchange = new DefaultServerWebExchange(oldRequest, new MockServerHttpResponse(),
				sessionManager, ServerCodecConfigurer.create(), new AcceptHeaderLocaleContextResolver());
		// @formatter:off
		Mono<OAuth2AuthorizationRequest> saveAndSaveAndRemove = this.repository
				.saveAuthorizationRequest(oldAuthorizationRequest, oldExchange)
				.then(this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange))
				.then(this.repository.removeAuthorizationRequest(this.exchange));
		StepVerifier.create(saveAndSaveAndRemove).expectNext(this.authorizationRequest)
				.verifyComplete();
		StepVerifier.create(this.repository.loadAuthorizationRequest(this.exchange))
				.verifyComplete();
		StepVerifier.create(this.repository.loadAuthorizationRequest(oldExchange))
				.expectNext(oldAuthorizationRequest)
				.verifyComplete();
		// @formatter:on
	}

	// gh-7327
	@Test
	public void removeAuthorizationRequestWhenMultipleThenRemovedAndSessionAttributeUpdated() {
		String oldState = "state0";
		// @formatter:off
		MockServerHttpRequest oldRequest = MockServerHttpRequest.get("/")
				.queryParam(OAuth2ParameterNames.STATE, oldState)
				.build();
		OAuth2AuthorizationRequest oldAuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/oauth2/authorize")
				.clientId("client-id")
				.redirectUri("http://localhost/client-1")
				.state(oldState)
				.build();
		// @formatter:on
		Map<String, Object> sessionAttrs = spy(new HashMap<>());
		WebSession session = mock(WebSession.class);
		given(session.getAttributes()).willReturn(sessionAttrs);
		WebSessionManager sessionManager = (e) -> Mono.just(session);
		this.exchange = new DefaultServerWebExchange(this.exchange.getRequest(), new MockServerHttpResponse(),
				sessionManager, ServerCodecConfigurer.create(), new AcceptHeaderLocaleContextResolver());
		ServerWebExchange oldExchange = new DefaultServerWebExchange(oldRequest, new MockServerHttpResponse(),
				sessionManager, ServerCodecConfigurer.create(), new AcceptHeaderLocaleContextResolver());
		// @formatter:off
		Mono<OAuth2AuthorizationRequest> saveAndSaveAndRemove = this.repository
				.saveAuthorizationRequest(oldAuthorizationRequest, oldExchange)
				.then(this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange))
				.then(this.repository.removeAuthorizationRequest(this.exchange));
		StepVerifier.create(saveAndSaveAndRemove).expectNext(this.authorizationRequest)
				.verifyComplete();
		StepVerifier.create(this.repository.loadAuthorizationRequest(this.exchange))
				.verifyComplete();
		// @formatter:on
		verify(sessionAttrs, times(3)).put(any(), any());
	}

}
