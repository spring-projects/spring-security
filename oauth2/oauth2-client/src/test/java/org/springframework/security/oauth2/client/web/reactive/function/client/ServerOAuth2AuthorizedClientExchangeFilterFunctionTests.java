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

package org.springframework.security.oauth2.client.web.reactive.function.client;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.codec.ByteBufferEncoder;
import org.springframework.core.codec.CharSequenceEncoder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.codec.EncoderHttpMessageWriter;
import org.springframework.http.codec.FormHttpMessageWriter;
import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.http.codec.ResourceHttpMessageWriter;
import org.springframework.http.codec.ServerSentEventHttpMessageWriter;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import org.springframework.http.codec.multipart.MultipartHttpMessageWriter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.reactive.function.client.OAuth2AuthorizedClientResolver.Request;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class ServerOAuth2AuthorizedClientExchangeFilterFunctionTests {
	@Mock
	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	@Mock
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	@Mock
	private OAuth2AuthorizedClientResolver authorizedClientResolver;

	@Mock
	private ServerWebExchange serverWebExchange;

	@Captor
	private ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor;

	private ServerOAuth2AuthorizedClientExchangeFilterFunction function;

	private MockExchangeFunction exchange = new MockExchangeFunction();

	private ClientRegistration registration = TestClientRegistrations.clientRegistration()
			.build();

	private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
			"token-0",
			Instant.now(),
			Instant.now().plus(Duration.ofDays(1)));

	@Before
	public void setup() {
		this.function = new ServerOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository, this.authorizedClientRepository);
	}

	@Test
	public void filterWhenAuthorizedClientNullThenAuthorizationHeaderNull() {
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
			.build();

		this.function.filter(request, this.exchange).block();

		assertThat(this.exchange.getRequest().headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
	}

	@Test
	public void filterWhenAuthorizedClientThenAuthorizationHeader() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.build();

		this.function.filter(request, this.exchange).block();

		assertThat(this.exchange.getRequest().headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer " + this.accessToken.getTokenValue());
	}

	@Test
	public void filterWhenExistingAuthorizationThenSingleAuthorizationHeader() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.header(HttpHeaders.AUTHORIZATION, "Existing")
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.build();

		this.function.filter(request, this.exchange).block();

		HttpHeaders headers = this.exchange.getRequest().headers();
		assertThat(headers.get(HttpHeaders.AUTHORIZATION)).containsOnly("Bearer " + this.accessToken.getTokenValue());
	}

	@Test
	public void filterWhenClientCredentialsTokenExpiredThenGetNewToken() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("test", "this");
		ClientRegistration registration = TestClientRegistrations.clientCredentials().build();
		String clientRegistrationId = registration.getClientId();

		this.function = new ServerOAuth2AuthorizedClientExchangeFilterFunction(this.authorizedClientRepository, this.authorizedClientResolver);

		OAuth2AccessToken newAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"new-token",
				Instant.now(),
				Instant.now().plus(Duration.ofDays(1)));
		OAuth2AuthorizedClient newAuthorizedClient = new OAuth2AuthorizedClient(registration,
				"principalName", newAccessToken, null);
		Request r = new Request(clientRegistrationId, authentication, null);
		when(this.authorizedClientResolver.clientCredentials(any(), any(), any())).thenReturn(Mono.just(newAuthorizedClient));
		when(this.authorizedClientResolver.createDefaultedRequest(any(), any(), any())).thenReturn(Mono.just(r));

		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));

		OAuth2AccessToken accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				issuedAt,
				accessTokenExpiresAt);


		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(registration,
				"principalName", accessToken, null);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.build();


		this.function.filter(request, this.exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();

		verify(this.authorizedClientResolver).clientCredentials(any(), any(), any());
		verify(this.authorizedClientResolver).createDefaultedRequest(any(), any(), any());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		ClientRequest request1 = requests.get(0);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer new-token");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenClientCredentialsTokenNotExpiredThenUseCurrentToken() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("test", "this");
		ClientRegistration registration = TestClientRegistrations.clientCredentials().build();

		this.function = new ServerOAuth2AuthorizedClientExchangeFilterFunction(this.authorizedClientRepository, this.authorizedClientResolver);

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(registration,
				"principalName", this.accessToken, null);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.build();

		this.function.filter(request, this.exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();

		verify(this.authorizedClientResolver, never()).clientCredentials(any(), any(), any());
		verify(this.authorizedClientResolver, never()).createDefaultedRequest(any(), any(), any());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		ClientRequest request1 = requests.get(0);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenRefreshRequiredThenRefresh() {
		when(this.authorizedClientRepository.saveAuthorizedClient(any(), any(), any())).thenReturn(Mono.empty());
		OAuth2AccessTokenResponse response = OAuth2AccessTokenResponse.withToken("token-1")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(3600)
				.refreshToken("refresh-1")
				.build();
		when(this.exchange.getResponse().body(any())).thenReturn(Mono.just(response));
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));

		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				issuedAt,
				accessTokenExpiresAt);

		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.build();

		TestingAuthenticationToken authentication = new TestingAuthenticationToken("test", "this");
		this.function.filter(request, this.exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();

		verify(this.authorizedClientRepository).saveAuthorizedClient(this.authorizedClientCaptor.capture(), eq(authentication), any());

		OAuth2AuthorizedClient newAuthorizedClient = authorizedClientCaptor.getValue();
		assertThat(newAuthorizedClient.getAccessToken()).isEqualTo(response.getAccessToken());
		assertThat(newAuthorizedClient.getRefreshToken()).isEqualTo(response.getRefreshToken());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(2);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com/login/oauth/access_token");
		assertThat(request0.method()).isEqualTo(HttpMethod.POST);
		assertThat(getBody(request0)).isEqualTo("grant_type=refresh_token&refresh_token=refresh-token");

		ClientRequest request1 = requests.get(1);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-1");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenRefreshRequiredThenRefreshAndResponseDoesNotContainRefreshToken() {
		when(this.authorizedClientRepository.saveAuthorizedClient(any(), any(), any())).thenReturn(Mono.empty());
		OAuth2AccessTokenResponse response = OAuth2AccessTokenResponse.withToken("token-1")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(3600)
//				.refreshToken(xxx)  // No refreshToken in response
				.build();
		when(this.exchange.getResponse().body(any())).thenReturn(Mono.just(response));
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));

		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				issuedAt,
				accessTokenExpiresAt);

		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.build();

		TestingAuthenticationToken authentication = new TestingAuthenticationToken("test", "this");
		this.function.filter(request, this.exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();

		verify(this.authorizedClientRepository).saveAuthorizedClient(this.authorizedClientCaptor.capture(), eq(authentication), any());

		OAuth2AuthorizedClient newAuthorizedClient = authorizedClientCaptor.getValue();
		assertThat(newAuthorizedClient.getAccessToken()).isEqualTo(response.getAccessToken());
		assertThat(newAuthorizedClient.getRefreshToken()).isEqualTo(authorizedClient.getRefreshToken());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(2);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com/login/oauth/access_token");
		assertThat(request0.method()).isEqualTo(HttpMethod.POST);
		assertThat(getBody(request0)).isEqualTo("grant_type=refresh_token&refresh_token=refresh-token");

		ClientRequest request1 = requests.get(1);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-1");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenRefreshRequiredAndEmptyReactiveSecurityContextThenSaved() {
		when(this.authorizedClientRepository.saveAuthorizedClient(any(), any(), any())).thenReturn(Mono.empty());
		OAuth2AccessTokenResponse response = OAuth2AccessTokenResponse.withToken("token-1")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(3600)
				.refreshToken("refresh-1")
				.build();
		when(this.exchange.getResponse().body(any())).thenReturn(Mono.just(response));
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));

		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				issuedAt,
				accessTokenExpiresAt);

		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.build();

		this.function.filter(request, this.exchange)
				.block();

		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), any(), any());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(2);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com/login/oauth/access_token");
		assertThat(request0.method()).isEqualTo(HttpMethod.POST);
		assertThat(getBody(request0)).isEqualTo("grant_type=refresh_token&refresh_token=refresh-token");

		ClientRequest request1 = requests.get(1);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-1");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenRefreshTokenNullThenShouldRefreshFalse() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.build();

		this.function.filter(request, this.exchange).block();

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenNotExpiredThenShouldRefreshFalse() {
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.build();

		this.function.filter(request, this.exchange).block();

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenClientRegistrationIdThenAuthorizedClientResolved() {
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		when(this.authorizedClientRepository.loadAuthorizedClient(any(), any(), any())).thenReturn(Mono.just(authorizedClient));
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(this.registration));
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(clientRegistrationId(this.registration.getRegistrationId()))
				.build();

		this.function.filter(request, this.exchange).block();

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenDefaultClientRegistrationIdThenAuthorizedClientResolved() {
		this.function.setDefaultClientRegistrationId(this.registration.getRegistrationId());
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		when(this.authorizedClientRepository.loadAuthorizedClient(any(), any(), any())).thenReturn(Mono.just(authorizedClient));
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(this.registration));
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.build();

		this.function.filter(request, this.exchange).block();

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenClientRegistrationIdFromAuthenticationThenAuthorizedClientResolved() {
		this.function.setDefaultOAuth2AuthorizedClient(true);

		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		when(this.authorizedClientRepository.loadAuthorizedClient(any(), any(), any())).thenReturn(Mono.just(authorizedClient));
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(this.registration));
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.build();

		OAuth2User user = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"), Collections
				.singletonMap("user", "rob"), "user");
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(user, user.getAuthorities(), "client-id");
		this.function
				.filter(request, this.exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenDefaultOAuth2AuthorizedClientFalseThenEmpty() {
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.build();

		OAuth2User user = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"), Collections
				.singletonMap("user", "rob"), "user");
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(user, user.getAuthorities(), "client-id");

		this.function
				.filter(request, this.exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		verifyZeroInteractions(this.clientRegistrationRepository, this.authorizedClientRepository);
	}

	@Test
	public void filterWhenClientRegistrationIdAndServerWebExchangeFromContextThenServerWebExchangeFromContext() {
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		when(this.authorizedClientRepository.loadAuthorizedClient(any(), any(), any())).thenReturn(Mono.just(authorizedClient));
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(this.registration));
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(clientRegistrationId(this.registration.getRegistrationId()))
				.build();

		this.function.filter(request, this.exchange)
				.subscriberContext(serverWebExchange())
				.block();

		verify(this.authorizedClientRepository).loadAuthorizedClient(eq(this.registration.getRegistrationId()), any(), eq(this.serverWebExchange));
	}

	private Context serverWebExchange() {
		return Context.of(ServerWebExchange.class, this.serverWebExchange);
	}

	private static String getBody(ClientRequest request) {
		final List<HttpMessageWriter<?>> messageWriters = new ArrayList<>();
		messageWriters.add(new EncoderHttpMessageWriter<>(new ByteBufferEncoder()));
		messageWriters.add(new EncoderHttpMessageWriter<>(CharSequenceEncoder.textPlainOnly()));
		messageWriters.add(new ResourceHttpMessageWriter());
		Jackson2JsonEncoder jsonEncoder = new Jackson2JsonEncoder();
		messageWriters.add(new EncoderHttpMessageWriter<>(jsonEncoder));
		messageWriters.add(new ServerSentEventHttpMessageWriter(jsonEncoder));
		messageWriters.add(new FormHttpMessageWriter());
		messageWriters.add(new EncoderHttpMessageWriter<>(CharSequenceEncoder.allMimeTypes()));
		messageWriters.add(new MultipartHttpMessageWriter(messageWriters));

		BodyInserter.Context context = new BodyInserter.Context() {
			@Override
			public List<HttpMessageWriter<?>> messageWriters() {
				return messageWriters;
			}

			@Override
			public Optional<ServerHttpRequest> serverRequest() {
				return Optional.empty();
			}

			@Override
			public Map<String, Object> hints() {
				return new HashMap<>();
			}
		};

		MockClientHttpRequest body = new MockClientHttpRequest(HttpMethod.GET, "/");
		request.body().insert(body, context).block();
		return body.getBodyAsString().block();
	}
}
