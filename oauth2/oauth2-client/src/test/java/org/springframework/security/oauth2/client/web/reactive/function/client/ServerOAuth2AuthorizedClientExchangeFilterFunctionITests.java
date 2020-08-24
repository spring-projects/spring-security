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

package org.springframework.security.oauth2.client.web.reactive.function.client;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Phil Clay
 */
public class ServerOAuth2AuthorizedClientExchangeFilterFunctionITests {

	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	private ServerOAuth2AuthorizedClientExchangeFilterFunction authorizedClientFilter;

	private MockWebServer server;

	private String serverUrl;

	private WebClient webClient;

	private Authentication authentication;

	private MockServerWebExchange exchange;

	@Before
	public void setUp() throws Exception {
		this.clientRegistrationRepository = mock(ReactiveClientRegistrationRepository.class);
		final ServerOAuth2AuthorizedClientRepository delegate = new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(
				new InMemoryReactiveOAuth2AuthorizedClientService(this.clientRegistrationRepository));
		this.authorizedClientRepository = spy(new ServerOAuth2AuthorizedClientRepository() {
			@Override
			public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(String clientRegistrationId,
					Authentication principal, ServerWebExchange exchange) {
				return delegate.loadAuthorizedClient(clientRegistrationId, principal, exchange);
			}

			@Override
			public Mono<Void> saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal,
					ServerWebExchange exchange) {
				return delegate.saveAuthorizedClient(authorizedClient, principal, exchange);
			}

			@Override
			public Mono<Void> removeAuthorizedClient(String clientRegistrationId, Authentication principal,
					ServerWebExchange exchange) {
				return delegate.removeAuthorizedClient(clientRegistrationId, principal, exchange);
			}
		});
		this.authorizedClientFilter = new ServerOAuth2AuthorizedClientExchangeFilterFunction(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		this.server = new MockWebServer();
		this.server.start();
		this.serverUrl = this.server.url("/").toString();
		// @formatter:off
		this.webClient = WebClient.builder()
				.filter(this.authorizedClientFilter)
				.build();
		// @formatter:on
		this.authentication = new TestingAuthenticationToken("principal", "password");
		this.exchange = MockServerWebExchange.builder(MockServerHttpRequest.get("/").build()).build();
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void requestWhenNotAuthorizedThenAuthorizeAndSendRequest() {
		// @formatter:off
		String accessTokenResponse = "{\n"
			+ "   \"access_token\": \"access-token-1234\",\n"
			+ "   \"token_type\": \"bearer\",\n"
			+ "   \"expires_in\": \"3600\",\n"
			+ "   \"scope\": \"read write\"\n"
			+ "}\n";
		String clientResponse = "{\n"
			+ "   \"attribute1\": \"value1\",\n"
			+ "   \"attribute2\": \"value2\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenResponse));
		this.server.enqueue(jsonResponse(clientResponse));
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials().tokenUri(this.serverUrl)
				.build();
		given(this.clientRegistrationRepository.findByRegistrationId(eq(clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(clientRegistration));
		// @formatter:off
		this.webClient.get()
				.uri(this.serverUrl)
				.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
						.clientRegistrationId(clientRegistration.getRegistrationId()))
				.retrieve()
				.bodyToMono(String.class)
				.subscriberContext(Context.of(ServerWebExchange.class, this.exchange))
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(this.authentication))
				.block();
		// @formatter:on
		assertThat(this.server.getRequestCount()).isEqualTo(2);
		ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor = ArgumentCaptor
				.forClass(OAuth2AuthorizedClient.class);
		verify(this.authorizedClientRepository).saveAuthorizedClient(authorizedClientCaptor.capture(),
				eq(this.authentication), eq(this.exchange));
		assertThat(authorizedClientCaptor.getValue().getClientRegistration()).isSameAs(clientRegistration);
	}

	@Test
	public void requestWhenAuthorizedButExpiredThenRefreshAndSendRequest() {
		// @formatter:off
		String accessTokenResponse = "{\n"
			+ "	\"access_token\": \"refreshed-access-token\",\n"
			+ "   \"token_type\": \"bearer\",\n"
			+ "   \"expires_in\": \"3600\"\n"
			+ "}\n";
		String clientResponse = "{\n"
			+ "	\"attribute1\": \"value1\",\n"
			+ "	\"attribute2\": \"value2\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenResponse));
		this.server.enqueue(jsonResponse(clientResponse));
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().tokenUri(this.serverUrl)
				.build();
		given(this.clientRegistrationRepository.findByRegistrationId(eq(clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(clientRegistration));
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"expired-access-token", issuedAt, expiresAt, new HashSet<>(Arrays.asList("read", "write")));
		OAuth2RefreshToken refreshToken = TestOAuth2RefreshTokens.refreshToken();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration,
				this.authentication.getName(), accessToken, refreshToken);
		doReturn(Mono.just(authorizedClient)).when(this.authorizedClientRepository).loadAuthorizedClient(
				eq(clientRegistration.getRegistrationId()), eq(this.authentication), eq(this.exchange));
		this.webClient.get().uri(this.serverUrl)
				.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
						.clientRegistrationId(clientRegistration.getRegistrationId()))
				.retrieve().bodyToMono(String.class)
				.subscriberContext(Context.of(ServerWebExchange.class, this.exchange))
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(this.authentication)).block();
		assertThat(this.server.getRequestCount()).isEqualTo(2);
		ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor = ArgumentCaptor
				.forClass(OAuth2AuthorizedClient.class);
		verify(this.authorizedClientRepository).saveAuthorizedClient(authorizedClientCaptor.capture(),
				eq(this.authentication), eq(this.exchange));
		OAuth2AuthorizedClient refreshedAuthorizedClient = authorizedClientCaptor.getValue();
		assertThat(refreshedAuthorizedClient.getClientRegistration()).isSameAs(clientRegistration);
		assertThat(refreshedAuthorizedClient.getAccessToken().getTokenValue()).isEqualTo("refreshed-access-token");
	}

	@Test
	public void requestMultipleWhenNoneAuthorizedThenAuthorizeAndSendRequest() {
		// @formatter:off
		String accessTokenResponse = "{\n"
			+ "   \"access_token\": \"access-token-1234\",\n"
			+ "   \"token_type\": \"bearer\",\n"
			+ "   \"expires_in\": \"3600\",\n"
			+ "   \"scope\": \"read write\"\n"
			+ "}\n";
		String clientResponse = "{\n"
			+ "   \"attribute1\": \"value1\",\n"
			+ "   \"attribute2\": \"value2\"\n"
			+ "}\n";
		// @formatter:on
		// Client 1
		this.server.enqueue(jsonResponse(accessTokenResponse));
		this.server.enqueue(jsonResponse(clientResponse));
		ClientRegistration clientRegistration1 = TestClientRegistrations.clientCredentials().registrationId("client-1")
				.tokenUri(this.serverUrl).build();
		given(this.clientRegistrationRepository.findByRegistrationId(eq(clientRegistration1.getRegistrationId())))
				.willReturn(Mono.just(clientRegistration1));
		// Client 2
		this.server.enqueue(jsonResponse(accessTokenResponse));
		this.server.enqueue(jsonResponse(clientResponse));
		ClientRegistration clientRegistration2 = TestClientRegistrations.clientCredentials().registrationId("client-2")
				.tokenUri(this.serverUrl).build();
		given(this.clientRegistrationRepository.findByRegistrationId(eq(clientRegistration2.getRegistrationId())))
				.willReturn(Mono.just(clientRegistration2));
		// @formatter:off
		this.webClient.get()
				.uri(this.serverUrl)
				.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
						.clientRegistrationId(clientRegistration1.getRegistrationId()))
				.retrieve()
				.bodyToMono(String.class)
				.flatMap((response) -> this.webClient.get()
						.uri(this.serverUrl)
						.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
								.clientRegistrationId(clientRegistration2.getRegistrationId()))
						.retrieve()
						.bodyToMono(String.class)
				)
				.subscriberContext(Context.of(ServerWebExchange.class, this.exchange))
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(this.authentication))
				.block();
		// @formatter:on
		assertThat(this.server.getRequestCount()).isEqualTo(4);
		ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor = ArgumentCaptor
				.forClass(OAuth2AuthorizedClient.class);
		verify(this.authorizedClientRepository, times(2)).saveAuthorizedClient(authorizedClientCaptor.capture(),
				eq(this.authentication), eq(this.exchange));
		assertThat(authorizedClientCaptor.getAllValues().get(0).getClientRegistration()).isSameAs(clientRegistration1);
		assertThat(authorizedClientCaptor.getAllValues().get(1).getClientRegistration()).isSameAs(clientRegistration2);
	}

	/**
	 * When a non-expired {@link OAuth2AuthorizedClient} exists but the resource server
	 * returns 401, then remove the {@link OAuth2AuthorizedClient} from the repository.
	 */
	@Test
	public void requestWhenUnauthorizedThenReAuthorize() {
		// @formatter:off
		String accessTokenResponse = "{\n"
			+ "   \"access_token\": \"access-token-1234\",\n"
			+ "   \"token_type\": \"bearer\",\n"
			+ "   \"expires_in\": \"3600\",\n"
			+ "   \"scope\": \"read write\"\n"
			+ "}\n";
		String clientResponse = "{\n"
			+ "   \"attribute1\": \"value1\",\n"
			+ "   \"attribute2\": \"value2\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.value()));
		this.server.enqueue(jsonResponse(accessTokenResponse));
		this.server.enqueue(jsonResponse(clientResponse));
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials().tokenUri(this.serverUrl)
				.build();
		given(this.clientRegistrationRepository.findByRegistrationId(eq(clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(clientRegistration));
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.scopes("read", "write");
		OAuth2RefreshToken refreshToken = TestOAuth2RefreshTokens.refreshToken();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration,
				this.authentication.getName(), accessToken, refreshToken);
		doReturn(Mono.just(authorizedClient)).doReturn(Mono.empty()).when(this.authorizedClientRepository)
				.loadAuthorizedClient(eq(clientRegistration.getRegistrationId()), eq(this.authentication),
						eq(this.exchange));
		// @formatter:off
		Mono<String> requestMono = this.webClient.get()
				.uri(this.serverUrl)
				.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
						.clientRegistrationId(clientRegistration.getRegistrationId()))
				.retrieve()
				.bodyToMono(String.class)
				.subscriberContext(Context.of(ServerWebExchange.class, this.exchange))
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		// @formatter:on
		// first try should fail, and remove the cached authorized client
		// @formatter:off
		assertThatExceptionOfType(WebClientResponseException.class)
				.isThrownBy(requestMono::block)
				.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		// @formatter:on
		assertThat(this.server.getRequestCount()).isEqualTo(1);
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), any(), any());
		verify(this.authorizedClientRepository).removeAuthorizedClient(eq(clientRegistration.getRegistrationId()),
				eq(this.authentication), eq(this.exchange));
		// second try should retrieve the authorized client and succeed
		requestMono.block();
		assertThat(this.server.getRequestCount()).isEqualTo(3);
		ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor = ArgumentCaptor
				.forClass(OAuth2AuthorizedClient.class);
		verify(this.authorizedClientRepository).saveAuthorizedClient(authorizedClientCaptor.capture(),
				eq(this.authentication), eq(this.exchange));
		assertThat(authorizedClientCaptor.getValue().getClientRegistration()).isSameAs(clientRegistration);
	}

	private MockResponse jsonResponse(String json) {
		// @formatter:off
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(json);
		// @formatter:on
	}

}
