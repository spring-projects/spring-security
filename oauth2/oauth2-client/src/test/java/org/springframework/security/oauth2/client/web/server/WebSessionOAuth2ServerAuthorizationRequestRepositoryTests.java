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

import java.util.Map;

import org.junit.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Rob Winch
 * @since 5.1
 */
public abstract class WebSessionOAuth2ServerAuthorizationRequestRepositoryTests {

	protected WebSessionOAuth2ServerAuthorizationRequestRepository repository;

	// @formatter:off
	protected OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri("https://example.com/oauth2/authorize")
			.clientId("client-id")
			.redirectUri("http://localhost/client-1")
			.state("state")
			.build();

	protected ServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/").queryParam(OAuth2ParameterNames.STATE, "state"));

	@Test
	public void loadAuthorizationRequestWhenNullExchangeThenIllegalArgumentException() {
		this.exchange = null;
		assertThatThrownBy(() -> this.repository.loadAuthorizationRequest(this.exchange))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizationRequestWhenNoSessionThenEmpty() {
		StepVerifier.create(this.repository.loadAuthorizationRequest(this.exchange))
				.verifyComplete();

		assertSessionStartedIs(false);
	}

	@Test
	public void loadAuthorizationRequestWhenSessionAndNoRequestThenEmpty() {
		Mono<OAuth2AuthorizationRequest> setAttrThenLoad = this.exchange.getSession()
				.map(WebSession::getAttributes).doOnNext(attrs -> attrs.put("foo", "bar"))
				.then(this.repository.loadAuthorizationRequest(this.exchange));

		StepVerifier.create(setAttrThenLoad)
				.verifyComplete();
	}

	@Test
	public void loadAuthorizationRequestWhenNoStateParamThenEmpty() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		Mono<OAuth2AuthorizationRequest> saveAndLoad = this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange)
				.then(this.repository.loadAuthorizationRequest(this.exchange));

		StepVerifier.create(saveAndLoad)
				.verifyComplete();
	}

	@Test
	public void loadAuthorizationRequestWhenSavedThenAuthorizationRequest() {
		Mono<OAuth2AuthorizationRequest> saveAndLoad = this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange)
				.then(this.repository.loadAuthorizationRequest(this.exchange));
		StepVerifier.create(saveAndLoad)
				.expectNext(this.authorizationRequest)
				.verifyComplete();
	}

	@Test
	public void saveAuthorizationRequestWhenAuthorizationRequestNullThenThrowsIllegalArgumentException() {
		this.authorizationRequest = null;
		assertThatThrownBy(() -> this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange))
				.isInstanceOf(IllegalArgumentException.class);
		assertSessionStartedIs(false);

	}

	@Test
	public void saveAuthorizationRequestWhenExchangeNullThenThrowsIllegalArgumentException() {
		this.exchange = null;
		assertThatThrownBy(() -> this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange))
				.isInstanceOf(IllegalArgumentException.class);

	}

	@Test
	public void removeAuthorizationRequestWhenExchangeNullThenThrowsIllegalArgumentException() {
		this.exchange = null;
		assertThatThrownBy(() -> this.repository.removeAuthorizationRequest(this.exchange))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizationRequestWhenNotPresentThenThrowsIllegalArgumentException() {
		StepVerifier.create(this.repository.removeAuthorizationRequest(this.exchange))
				.verifyComplete();
		assertSessionStartedIs(false);
	}

	@Test
	public void removeAuthorizationRequestWhenPresentThenFoundAndRemoved() {
		Mono<OAuth2AuthorizationRequest> saveAndRemove = this.repository
				.saveAuthorizationRequest(this.authorizationRequest, this.exchange)
				.then(this.repository.removeAuthorizationRequest(this.exchange));

		StepVerifier.create(saveAndRemove).expectNext(this.authorizationRequest)
				.verifyComplete();

		StepVerifier.create(this.exchange.getSession()
				.map(WebSession::getAttributes)
				.map(Map::isEmpty))
				.expectNext(true)
				.verifyComplete();
	}

	// gh-5599
	@Test
	public void removeAuthorizationRequestWhenStateMissingThenNoErrors() {
		MockServerHttpRequest otherState = MockServerHttpRequest.get("/")
				.queryParam(OAuth2ParameterNames.STATE, "other")
				.build();
		ServerWebExchange otherStateExchange = this.exchange.mutate()
				.request(otherState)
				.build();
		Mono<OAuth2AuthorizationRequest> saveAndRemove = this.repository
				.saveAuthorizationRequest(this.authorizationRequest, this.exchange)
				.then(this.repository.removeAuthorizationRequest(otherStateExchange));

		StepVerifier.create(saveAndRemove)
				.verifyComplete();
	}

	private void assertSessionStartedIs(boolean expected) {
		Mono<Boolean> isStarted = this.exchange.getSession().map(WebSession::isStarted);
		StepVerifier.create(isStarted)
			.expectNext(expected)
			.verifyComplete();
	}
}
