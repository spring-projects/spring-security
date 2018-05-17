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

package org.springframework.security.oauth2.client.web;

import org.junit.Test;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.adapter.DefaultServerWebExchange;
import org.springframework.web.server.i18n.AcceptHeaderLocaleContextResolver;
import org.springframework.web.server.session.WebSessionManager;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class WebSessionOAuth2ReactiveAuthorizationRequestRepositoryTests {

	private WebSessionOAuth2ReactiveAuthorizationRequestRepository repository =
			new WebSessionOAuth2ReactiveAuthorizationRequestRepository();

	private OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri("https://example.com/oauth2/authorize")
			.clientId("clientId")
			.redirectUri("http://localhost/client-1")
			.state("state")
			.build();

	private String clientRegistrationId = "github";

	private ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(this.clientRegistrationId)
			.redirectUriTemplate("{baseUrl}/{action}/oauth2/code/{registrationId}")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.scope("read:user")
			.authorizationUri("https://github.com/login/oauth/authorize")
			.tokenUri("https://github.com/login/oauth/access_token")
			.userInfoUri("https://api.github.com/user")
			.userNameAttributeName("id")
			.clientName("GitHub")
			.clientId("clientId")
			.clientSecret("clientSecret")
			.build();

	private ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/")
			.queryParam(OAuth2ParameterNames.STATE, "state"));

	@Test
	public void removeAuthorizationRequestWhenNullExchangeThenIllegalArgumentException() {
		this.exchange = null;
		assertThatThrownBy(() -> this.repository.removeAuthorizationRequest(this.exchange, clientRegistration))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizationRequestWhenNoSessionThenEmpty() {
		StepVerifier.create(this.repository.removeAuthorizationRequest(this.exchange, clientRegistration))
				.verifyComplete();

		assertSessionStartedIs(false);
	}

	@Test
	public void removeAuthorizationRequestWhenSessionAndNoRequestThenEmpty() {
		Mono<OAuth2AuthorizationRequest> setAttrThenLoad = this.exchange.getSession()
				.map(WebSession::getAttributes).doOnNext(attrs -> attrs.put("foo", "bar"))
				.then(this.repository.removeAuthorizationRequest(this.exchange, clientRegistration));

		StepVerifier.create(setAttrThenLoad)
				.verifyComplete();
	}

	@Test
	public void removeAuthorizationRequestWhenNoStateParamThenEmpty() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		Mono<OAuth2AuthorizationRequest> saveAndLoad = this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange, clientRegistration)
				.then(this.repository.removeAuthorizationRequest(this.exchange, clientRegistration));

		StepVerifier.create(saveAndLoad)
				.verifyComplete();
	}

	@Test
	public void removeAuthorizationRequestWhenSavedThenAuthorizationRequest() {
		Mono<OAuth2AuthorizationRequest> saveAndLoad = this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange, clientRegistration)
				.then(this.repository.removeAuthorizationRequest(this.exchange, clientRegistration));
		StepVerifier.create(saveAndLoad)
				.expectNext(this.authorizationRequest)
				.verifyComplete();
	}

	@Test
	public void removeAuthorizationRequestWhenMultipleSavedThenAuthorizationRequest() {
		String oldState = "state0";
		MockServerHttpRequest oldRequest = MockServerHttpRequest.get("/")
				.queryParam(OAuth2ParameterNames.STATE, oldState).build();

		OAuth2AuthorizationRequest oldAuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/oauth2/authorize")
				.clientId("clientId")
				.redirectUri("http://localhost/client-1")
				.state(oldState)
				.build();

		WebSessionManager sessionManager = e -> this.exchange.getSession();

		this.exchange = new DefaultServerWebExchange(this.exchange.getRequest(), new MockServerHttpResponse(), sessionManager,
				ServerCodecConfigurer.create(), new AcceptHeaderLocaleContextResolver());
		ServerWebExchange oldExchange = new DefaultServerWebExchange(oldRequest, new MockServerHttpResponse(), sessionManager,
				ServerCodecConfigurer.create(), new AcceptHeaderLocaleContextResolver());

		Mono<OAuth2AuthorizationRequest> saveAndSaveAndLoad = this.repository.saveAuthorizationRequest(oldAuthorizationRequest, oldExchange, clientRegistration)
				.then(this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange, clientRegistration))
				.then(this.repository.removeAuthorizationRequest(oldExchange, clientRegistration));

		StepVerifier.create(saveAndSaveAndLoad)
				.expectNext(oldAuthorizationRequest)
				.verifyComplete();

		StepVerifier.create(this.repository.removeAuthorizationRequest(this.exchange, clientRegistration))
				.expectNext(this.authorizationRequest)
				.verifyComplete();
	}

	@Test
	public void saveAuthorizationRequestWhenAuthorizationRequestNullThenThrowsIllegalArgumentException() {
		this.authorizationRequest = null;
		assertThatThrownBy(() -> this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange, clientRegistration))
				.isInstanceOf(IllegalArgumentException.class);
		assertSessionStartedIs(false);

	}

	@Test
	public void saveAuthorizationRequestWhenExchangeNullThenThrowsIllegalArgumentException() {
		this.exchange = null;
		assertThatThrownBy(() -> this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange, clientRegistration))
				.isInstanceOf(IllegalArgumentException.class);

	}

	@Test
	public void removeAuthorizationRequestWhenExchangeNullThenThrowsIllegalArgumentException() {
		this.exchange = null;
		assertThatThrownBy(() -> this.repository.removeAuthorizationRequest(this.exchange, clientRegistration))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizationRequestWhenNotPresentThenThrowsIllegalArgumentException() {
		StepVerifier.create(this.repository.removeAuthorizationRequest(this.exchange, clientRegistration))
				.verifyComplete();
		assertSessionStartedIs(false);
	}

	@Test
	public void removeAuthorizationRequestWhenPresentThenFoundAndRemoved() {
		Mono<OAuth2AuthorizationRequest> saveAndRemove = this.repository
				.saveAuthorizationRequest(this.authorizationRequest, this.exchange, clientRegistration)
				.then(this.repository.removeAuthorizationRequest(this.exchange, clientRegistration));

		StepVerifier.create(saveAndRemove).expectNext(this.authorizationRequest)
				.verifyComplete();

		StepVerifier.create(this.exchange.getSession()
				.map(WebSession::getAttributes)
				.map(Map::isEmpty))
				.expectNext(true)
				.verifyComplete();
	}

	@Test
	public void removeAuthorizationRequestWhenMultipleThenOnlyOneRemoved() {
		String oldState = "state0";
		MockServerHttpRequest oldRequest = MockServerHttpRequest.get("/")
				.queryParam(OAuth2ParameterNames.STATE, oldState).build();

		OAuth2AuthorizationRequest oldAuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/oauth2/authorize")
				.clientId("clientId")
				.redirectUri("http://localhost/client-1")
				.state(oldState)
				.build();

		WebSessionManager sessionManager = e -> this.exchange.getSession();

		this.exchange = new DefaultServerWebExchange(this.exchange.getRequest(), new MockServerHttpResponse(), sessionManager,
				ServerCodecConfigurer.create(), new AcceptHeaderLocaleContextResolver());
		ServerWebExchange oldExchange = new DefaultServerWebExchange(oldRequest, new MockServerHttpResponse(), sessionManager,
				ServerCodecConfigurer.create(), new AcceptHeaderLocaleContextResolver());

		Mono<OAuth2AuthorizationRequest> saveAndSaveAndRemove = this.repository.saveAuthorizationRequest(oldAuthorizationRequest, oldExchange, clientRegistration)
				.then(this.repository.saveAuthorizationRequest(this.authorizationRequest, this.exchange, clientRegistration))
				.then(this.repository.removeAuthorizationRequest(this.exchange, clientRegistration));

		StepVerifier.create(saveAndSaveAndRemove)
				.expectNext(this.authorizationRequest)
				.verifyComplete();

		StepVerifier.create(this.repository.removeAuthorizationRequest(this.exchange, clientRegistration))
				.verifyComplete();

		StepVerifier.create(this.repository.removeAuthorizationRequest(oldExchange, clientRegistration))
				.expectNext(oldAuthorizationRequest)
				.verifyComplete();
	}

	private void assertSessionStartedIs(boolean expected) {
		Mono<Boolean> isStarted = this.exchange.getSession().map(WebSession::isStarted);
		StepVerifier.create(isStarted)
			.expectNext(expected)
			.verifyComplete();
	}
}
