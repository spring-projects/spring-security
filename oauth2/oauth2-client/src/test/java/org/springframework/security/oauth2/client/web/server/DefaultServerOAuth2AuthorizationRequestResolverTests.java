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

package org.springframework.security.oauth2.client.web.server;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultServerOAuth2AuthorizationRequestResolverTests {
	@Mock
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	private DefaultServerOAuth2AuthorizationRequestResolver resolver;

	private ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	@Before
	public void setup() {
		this.resolver = new DefaultServerOAuth2AuthorizationRequestResolver(this.clientRegistrationRepository);
	}

	@Test
	public void resolveWhenNotMatchThenNull() {
		assertThat(resolve("/")).isNull();
	}

	@Test
	public void resolveWhenClientRegistrationNotFoundMatchThenBadRequest() {
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(
				Mono.empty());

		ResponseStatusException expected = catchThrowableOfType(() -> resolve("/oauth2/authorization/not-found-id"), ResponseStatusException.class);

		assertThat(expected.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
	}

	@Test
	public void resolveWhenClientRegistrationFoundThenWorks() {
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(
				Mono.just(this.registration));

		OAuth2AuthorizationRequest request = resolve("/oauth2/authorization/not-found-id");

		assertThat(request.getAuthorizationRequestUri()).matches("https://example.com/login/oauth/authorize\\?" +
				"response_type=code&client_id=client-id&" +
				"scope=read:user&state=.*?&" +
				"redirect_uri=/login/oauth2/code/registration-id");
	}

	private OAuth2AuthorizationRequest resolve(String path) {
		ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get(path));
		return this.resolver.resolve(exchange).block();
	}

	@Test
	public void resolveWhenForwardedHeadersClientRegistrationFoundThenWorks() {
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(
				Mono.just(this.registration));
		ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/oauth2/authorization/id").header("X-Forwarded-Host", "evil.com"));

		OAuth2AuthorizationRequest request = this.resolver.resolve(exchange).block();

		assertThat(request.getAuthorizationRequestUri()).matches("https://example.com/login/oauth/authorize\\?" +
				"response_type=code&client_id=client-id&" +
				"scope=read:user&state=.*?&" +
				"redirect_uri=/login/oauth2/code/registration-id");
	}
}
