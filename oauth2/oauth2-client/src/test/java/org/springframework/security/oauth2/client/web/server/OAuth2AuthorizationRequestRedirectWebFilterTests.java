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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.handler.FilteringWebHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * @author Rob Winch
 * @since 5.1
 */
@ExtendWith(MockitoExtension.class)
public class OAuth2AuthorizationRequestRedirectWebFilterTests {

	@Mock
	private ReactiveClientRegistrationRepository clientRepository;

	@Mock
	private ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authzRequestRepository;

	@Mock
	private ServerRequestCache requestCache;

	private ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	private OAuth2AuthorizationRequestRedirectWebFilter filter;

	private WebTestClient client;

	@BeforeEach
	public void setup() {
		this.filter = new OAuth2AuthorizationRequestRedirectWebFilter(this.clientRepository);
		this.filter.setAuthorizationRequestRepository(this.authzRequestRepository);
		FilteringWebHandler webHandler = new FilteringWebHandler((e) -> e.getResponse().setComplete(),
				Arrays.asList(this.filter));
		this.client = WebTestClient.bindToWebHandler(webHandler).build();
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryNullThenIllegalArgumentException() {
		this.clientRepository = null;
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2AuthorizationRequestRedirectWebFilter(this.clientRepository));
	}

	@Test
	public void setterWhenAuthorizationRedirectStrategyNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAuthorizationRedirectStrategy(null));
	}

	@Test
	public void filterWhenDoesNotMatchThenClientRegistrationRepositoryNotSubscribed() {
		// @formatter:off
		this.client.get()
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
		verifyNoInteractions(this.clientRepository, this.authzRequestRepository);
	}

	@Test
	public void filterWhenDoesMatchThenClientRegistrationRepositoryNotSubscribed() {
		given(this.clientRepository.findByRegistrationId(this.registration.getRegistrationId()))
				.willReturn(Mono.just(this.registration));
		given(this.authzRequestRepository.saveAuthorizationRequest(any(), any())).willReturn(Mono.empty());
		// @formatter:off
		FluxExchangeResult<String> result = this.client.get()
				.uri("https://example.com/oauth2/authorization/registration-id")
				.exchange()
				.expectStatus().is3xxRedirection()
				.returnResult(String.class);
		// @formatter:on
		result.assertWithDiagnostics(() -> {
			URI location = result.getResponseHeaders().getLocation();
			assertThat(location).hasScheme("https").hasHost("example.com").hasPath("/login/oauth/authorize")
					.hasParameter("response_type", "code").hasParameter("client_id", "client-id")
					.hasParameter("scope", "read:user").hasParameter("state")
					.hasParameter("redirect_uri", "https://example.com/login/oauth2/code/registration-id");
		});
		verify(this.authzRequestRepository).saveAuthorizationRequest(any(), any());
	}

	// gh-5520
	@Test
	public void filterWhenDoesMatchThenResolveRedirectUriExpandedExcludesQueryString() {
		given(this.clientRepository.findByRegistrationId(this.registration.getRegistrationId()))
				.willReturn(Mono.just(this.registration));
		given(this.authzRequestRepository.saveAuthorizationRequest(any(), any())).willReturn(Mono.empty());
		// @formatter:off
		FluxExchangeResult<String> result = this.client.get()
				.uri("https://example.com/oauth2/authorization/registration-id?foo=bar").exchange().expectStatus()
				.is3xxRedirection().returnResult(String.class);
		result.assertWithDiagnostics(() -> {
			URI location = result.getResponseHeaders().getLocation();
			assertThat(location)
					.hasScheme("https")
					.hasHost("example.com")
					.hasPath("/login/oauth/authorize")
					.hasParameter("response_type", "code")
					.hasParameter("client_id", "client-id")
					.hasParameter("scope", "read:user")
					.hasParameter("state")
					.hasParameter("redirect_uri", "https://example.com/login/oauth2/code/registration-id");
		});
		// @formatter:on
	}

	@Test
	public void filterWhenExceptionThenRedirected() {
		given(this.clientRepository.findByRegistrationId(this.registration.getRegistrationId()))
				.willReturn(Mono.just(this.registration));
		given(this.authzRequestRepository.saveAuthorizationRequest(any(), any())).willReturn(Mono.empty());
		FilteringWebHandler webHandler = new FilteringWebHandler(
				(e) -> Mono.error(new ClientAuthorizationRequiredException(this.registration.getRegistrationId())),
				Arrays.asList(this.filter));
		// @formatter:off
		this.client = WebTestClient.bindToWebHandler(webHandler)
				.build();
		FluxExchangeResult<String> result = this.client.get()
				.uri("https://example.com/foo")
				.exchange()
				.expectStatus().is3xxRedirection()
				.returnResult(String.class);
		// @formatter:on
	}

	@Test
	public void filterWhenExceptionThenSaveRequestSessionAttribute() {
		given(this.clientRepository.findByRegistrationId(this.registration.getRegistrationId()))
				.willReturn(Mono.just(this.registration));
		given(this.authzRequestRepository.saveAuthorizationRequest(any(), any())).willReturn(Mono.empty());
		this.filter.setRequestCache(this.requestCache);
		given(this.requestCache.saveRequest(any())).willReturn(Mono.empty());
		FilteringWebHandler webHandler = new FilteringWebHandler(
				(e) -> Mono.error(new ClientAuthorizationRequiredException(this.registration.getRegistrationId())),
				Arrays.asList(this.filter));
		// @formatter:off
		this.client = WebTestClient.bindToWebHandler(webHandler)
				.build();
		this.client.get()
				.uri("https://example.com/foo")
				.exchange()
				.expectStatus().is3xxRedirection()
				.returnResult(String.class);
		// @formatter:on
		verify(this.requestCache).saveRequest(any());
	}

	@Test
	public void filterWhenPathMatchesThenRequestSessionAttributeNotSaved() {
		given(this.clientRepository.findByRegistrationId(this.registration.getRegistrationId()))
				.willReturn(Mono.just(this.registration));
		given(this.authzRequestRepository.saveAuthorizationRequest(any(), any())).willReturn(Mono.empty());
		this.filter.setRequestCache(this.requestCache);
		// @formatter:off
		this.client.get()
				.uri("https://example.com/oauth2/authorization/registration-id")
				.exchange()
				.expectStatus().is3xxRedirection()
				.returnResult(String.class);
		// @formatter:on
		verifyNoInteractions(this.requestCache);
	}

	@Test
	public void filterWhenCustomRedirectStrategySetThenRedirectUriInResponseBody() {
		given(this.clientRepository.findByRegistrationId(this.registration.getRegistrationId()))
				.willReturn(Mono.just(this.registration));
		given(this.authzRequestRepository.saveAuthorizationRequest(any(), any())).willReturn(Mono.empty());
		ServerRedirectStrategy customRedirectStrategy = (exchange, location) -> {
			ServerHttpResponse response = exchange.getResponse();
			response.setStatusCode(HttpStatus.OK);
			response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
			DataBuffer buffer = exchange.getResponse().bufferFactory()
					.wrap(location.toASCIIString().getBytes(StandardCharsets.UTF_8));

			return exchange.getResponse().writeWith(Flux.just(buffer));
		};
		this.filter.setAuthorizationRedirectStrategy(customRedirectStrategy);
		this.filter.setRequestCache(this.requestCache);

		FluxExchangeResult<String> result = this.client.get()
				.uri("https://example.com/oauth2/authorization/registration-id").exchange().expectHeader()
				.contentType(MediaType.TEXT_PLAIN).expectStatus().isOk().returnResult(String.class);

		// @formatter:off
		StepVerifier.create(result.getResponseBody())
				.assertNext((uri) -> {
					URI location = URI.create(uri);

					assertThat(location)
							.hasScheme("https")
							.hasHost("example.com")
							.hasPath("/login/oauth/authorize")
							.hasParameter("response_type", "code")
							.hasParameter("client_id", "client-id")
							.hasParameter("scope", "read:user")
							.hasParameter("state")
							.hasParameter("redirect_uri", "https://example.com/login/oauth2/code/registration-id");
				})
				.verifyComplete();
		// @formatter:on

		verifyNoInteractions(this.requestCache);
	}

}
