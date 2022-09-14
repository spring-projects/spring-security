/*
 * Copyright 2002-2022 the original author or authors.
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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.publisher.PublisherProbe;
import reactor.util.context.Context;

import org.springframework.core.codec.ByteBufferEncoder;
import org.springframework.core.codec.CharSequenceEncoder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.EncoderHttpMessageWriter;
import org.springframework.http.codec.FormHttpMessageWriter;
import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.http.codec.ResourceHttpMessageWriter;
import org.springframework.http.codec.ServerSentEventHttpMessageWriter;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import org.springframework.http.codec.multipart.MultipartHttpMessageWriter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.JwtBearerReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.JwtBearerGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Rob Winch
 * @since 5.1
 */
@ExtendWith(MockitoExtension.class)
public class ServerOAuth2AuthorizedClientExchangeFilterFunctionTests {

	@Mock
	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	@Mock
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	@Mock
	private ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient;

	@Mock
	private ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenTokenResponseClient;

	@Mock
	private ReactiveOAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> passwordTokenResponseClient;

	@Mock
	private ReactiveOAuth2AccessTokenResponseClient<JwtBearerGrantRequest> jwtBearerTokenResponseClient;

	@Mock
	private ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler;

	@Captor
	private ArgumentCaptor<OAuth2AuthorizationException> authorizationExceptionCaptor;

	@Captor
	private ArgumentCaptor<Authentication> authenticationCaptor;

	@Captor
	private ArgumentCaptor<Map<String, Object>> attributesCaptor;

	private ServerWebExchange serverWebExchange = MockServerWebExchange.builder(MockServerHttpRequest.get("/")).build();

	@Captor
	private ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor;

	private ServerOAuth2AuthorizedClientExchangeFilterFunction function;

	private MockExchangeFunction exchange = new MockExchangeFunction();

	private ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token-0",
			Instant.now(), Instant.now().plus(Duration.ofDays(1)));

	private DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager;

	@BeforeEach
	public void setup() {
		// @formatter:off
		JwtBearerReactiveOAuth2AuthorizedClientProvider jwtBearerAuthorizedClientProvider = new JwtBearerReactiveOAuth2AuthorizedClientProvider();
		jwtBearerAuthorizedClientProvider.setAccessTokenResponseClient(this.jwtBearerTokenResponseClient);
		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder
				.builder()
				.authorizationCode()
				.refreshToken(
						(configurer) -> configurer.accessTokenResponseClient(this.refreshTokenTokenResponseClient))
				.clientCredentials(
						(configurer) -> configurer.accessTokenResponseClient(this.clientCredentialsTokenResponseClient))
				.password((configurer) -> configurer.accessTokenResponseClient(this.passwordTokenResponseClient))
				.provider(jwtBearerAuthorizedClientProvider)
				.build();
		// @formatter:on
		this.authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		this.authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
		this.function = new ServerOAuth2AuthorizedClientExchangeFilterFunction(this.authorizedClientManager);
	}

	private void setupMocks() {
		setupMockSaveAuthorizedClient();
		setupMockHeaders();
	}

	private void setupMockSaveAuthorizedClient() {
		given(this.authorizedClientRepository.saveAuthorizedClient(any(), any(), any())).willReturn(Mono.empty());
	}

	private void setupMockHeaders() {
		given(this.exchange.getResponse().headers()).willReturn(mock(ClientResponse.Headers.class));
	}

	@Test
	public void constructorWhenAuthorizedClientManagerIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new ServerOAuth2AuthorizedClientExchangeFilterFunction(null));
	}

	@Test
	public void filterWhenAuthorizedClientNullThenAuthorizationHeaderNull() {
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com")).build();
		this.function.filter(request, this.exchange).block();
		assertThat(this.exchange.getRequest().headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
	}

	@Test
	public void filterWhenAuthorizedClientThenAuthorizationHeader() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		// @formatter:off
		this.function.filter(request, this.exchange).contextWrite(serverWebExchange())
				.block();
		// @formatter:on
		assertThat(this.exchange.getRequest().headers().getFirst(HttpHeaders.AUTHORIZATION))
				.isEqualTo("Bearer " + this.accessToken.getTokenValue());
	}

	@Test
	public void filterWhenExistingAuthorizationThenSingleAuthorizationHeader() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.header(HttpHeaders.AUTHORIZATION, "Existing")
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		// @formatter:on
		this.function.filter(request, this.exchange).contextWrite(serverWebExchange()).block();
		HttpHeaders headers = this.exchange.getRequest().headers();
		assertThat(headers.get(HttpHeaders.AUTHORIZATION)).containsOnly("Bearer " + this.accessToken.getTokenValue());
	}

	@Test
	public void filterWhenClientCredentialsTokenExpiredThenGetNewToken() {
		setupMocks();
		// @formatter:off
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse
				.withToken("new-token")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(360)
				.build();
		// @formatter:on
		given(this.clientCredentialsTokenResponseClient.getTokenResponse(any()))
				.willReturn(Mono.just(accessTokenResponse));
		ClientRegistration registration = TestClientRegistrations.clientCredentials().build();
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(), issuedAt, accessTokenExpiresAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(registration, "principalName", accessToken,
				null);
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("test", "this");
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		this.function.filter(request, this.exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.contextWrite(serverWebExchange())
				.block();
		// @formatter:on
		verify(this.clientCredentialsTokenResponseClient).getTokenResponse(any());
		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), eq(authentication), any());
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
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(registration, "principalName",
				this.accessToken, null);
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		this.function.filter(request, this.exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.contextWrite(serverWebExchange())
				.block();
		// @formatter:on
		verify(this.clientCredentialsTokenResponseClient, never()).getTokenResponse(any());
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
		setupMocks();
		OAuth2AccessTokenResponse response = OAuth2AccessTokenResponse.withToken("token-1")
				.tokenType(OAuth2AccessToken.TokenType.BEARER).expiresIn(3600).refreshToken("refresh-1").build();
		given(this.refreshTokenTokenResponseClient.getTokenResponse(any())).willReturn(Mono.just(response));
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));
		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(), this.accessToken.getTokenValue(),
				issuedAt, accessTokenExpiresAt);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		// @formatter:on
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("test", "this");
		// @formatter:off
		this.function.filter(request, this.exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.contextWrite(serverWebExchange())
				.block();
		// @formatter:on
		verify(this.refreshTokenTokenResponseClient).getTokenResponse(any());
		verify(this.authorizedClientRepository).saveAuthorizedClient(this.authorizedClientCaptor.capture(),
				eq(authentication), any());
		OAuth2AuthorizedClient newAuthorizedClient = this.authorizedClientCaptor.getValue();
		assertThat(newAuthorizedClient.getAccessToken()).isEqualTo(response.getAccessToken());
		assertThat(newAuthorizedClient.getRefreshToken()).isEqualTo(response.getRefreshToken());
		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-1");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenRefreshRequiredAndEmptyReactiveSecurityContextThenSaved() {
		setupMocks();
		OAuth2AccessTokenResponse response = OAuth2AccessTokenResponse.withToken("token-1")
				.tokenType(OAuth2AccessToken.TokenType.BEARER).expiresIn(3600).refreshToken("refresh-1").build();
		given(this.refreshTokenTokenResponseClient.getTokenResponse(any())).willReturn(Mono.just(response));
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));
		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(), this.accessToken.getTokenValue(),
				issuedAt, accessTokenExpiresAt);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		this.function.filter(request, this.exchange)
				.contextWrite(serverWebExchange())
				.block();
		// @formatter:on
		verify(this.refreshTokenTokenResponseClient).getTokenResponse(any());
		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), any(), any());
		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-1");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenJwtBearerClientNotAuthorizedThenExchangeToken() {
		setupMocks();
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("exchanged-token")
				.tokenType(OAuth2AccessToken.TokenType.BEARER).expiresIn(360).build();
		given(this.jwtBearerTokenResponseClient.getTokenResponse(any())).willReturn(Mono.just(accessTokenResponse));
		// @formatter:off
		ClientRegistration registration = ClientRegistration.withRegistrationId("jwt-bearer")
				.clientId("client-id")
				.clientSecret("client-secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
				.scope("read", "write")
				.tokenUri("https://example.com/oauth/token")
				.build();
		// @formatter:on
		given(this.clientRegistrationRepository.findByRegistrationId(eq(registration.getRegistrationId())))
				.willReturn(Mono.just(registration));
		Jwt jwtAssertion = TestJwts.jwt().build();
		Authentication jwtAuthentication = new TestingAuthenticationToken(jwtAssertion, jwtAssertion);
		given(this.authorizedClientRepository.loadAuthorizedClient(eq(registration.getRegistrationId()),
				eq(jwtAuthentication), any())).willReturn(Mono.empty());
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId(registration.getRegistrationId()))
				.build();
		// @formatter:on
		this.function.filter(request, this.exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(jwtAuthentication))
				.contextWrite(serverWebExchange()).block();
		verify(this.jwtBearerTokenResponseClient).getTokenResponse(any());
		verify(this.authorizedClientRepository).loadAuthorizedClient(eq(registration.getRegistrationId()),
				eq(jwtAuthentication), any());
		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), eq(jwtAuthentication), any());
		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		ClientRequest request1 = requests.get(0);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer exchanged-token");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenRefreshTokenNullThenShouldRefreshFalse() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		this.function.filter(request, this.exchange)
				.contextWrite(serverWebExchange())
				.block();
		// @formatter:on
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
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		this.function.filter(request, this.exchange)
				.contextWrite(serverWebExchange())
				.block();
		// @formatter:on
		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenUnauthorizedThenInvokeFailureHandler() {
		setupMockHeaders();
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		PublisherProbe<Void> publisherProbe = PublisherProbe.empty();
		given(this.authorizationFailureHandler.onAuthorizationFailure(any(), any(), any()))
				.willReturn(publisherProbe.mono());
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		// @formatter:on
		given(this.exchange.getResponse().rawStatusCode()).willReturn(HttpStatus.UNAUTHORIZED.value());
		this.function.filter(request, this.exchange).contextWrite(serverWebExchange()).block();
		assertThat(publisherProbe.wasSubscribed()).isTrue();
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		assertThat(this.authorizationExceptionCaptor.getValue())
				.isInstanceOfSatisfying(ClientAuthorizationException.class, (ex) -> {
					assertThat(ex.getClientRegistrationId()).isEqualTo(this.registration.getRegistrationId());
					assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_token");
					assertThat(ex).hasNoCause();
					assertThat(ex).hasMessageContaining("[invalid_token]");
				});
		assertThat(this.authenticationCaptor.getValue()).isInstanceOf(AnonymousAuthenticationToken.class);
		assertThat(this.attributesCaptor.getValue())
				.containsExactly(entry(ServerWebExchange.class.getName(), this.serverWebExchange));
	}

	@Test
	public void filterWhenUnauthorizedWithWebClientExceptionThenInvokeFailureHandler() {
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		PublisherProbe<Void> publisherProbe = PublisherProbe.empty();
		given(this.authorizationFailureHandler.onAuthorizationFailure(any(), any(), any()))
				.willReturn(publisherProbe.mono());
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		// @formatter:on
		WebClientResponseException exception = WebClientResponseException.create(HttpStatus.UNAUTHORIZED.value(),
				HttpStatus.UNAUTHORIZED.getReasonPhrase(), HttpHeaders.EMPTY, new byte[0], StandardCharsets.UTF_8);
		ExchangeFunction throwingExchangeFunction = (r) -> Mono.error(exception);
		// @formatter:off
		assertThatExceptionOfType(WebClientResponseException.class)
				.isThrownBy(() -> this.function
					.filter(request, throwingExchangeFunction)
						.contextWrite(serverWebExchange())
						.block()
				)
				.isEqualTo(exception);
		// @formatter:on
		assertThat(publisherProbe.wasSubscribed()).isTrue();
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		// @formatter:off
		assertThat(this.authorizationExceptionCaptor.getValue())
				.isInstanceOfSatisfying(ClientAuthorizationException.class, (ex) -> {
					assertThat(ex.getClientRegistrationId()).isEqualTo(this.registration.getRegistrationId());
					assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_token");
					assertThat(ex).hasCause(exception);
					assertThat(ex).hasMessageContaining("[invalid_token]");
				});
		// @formatter:on
		assertThat(this.authenticationCaptor.getValue()).isInstanceOf(AnonymousAuthenticationToken.class);
		assertThat(this.attributesCaptor.getValue())
				.containsExactly(entry(ServerWebExchange.class.getName(), this.serverWebExchange));
	}

	@Test
	public void filterWhenForbiddenThenInvokeFailureHandler() {
		setupMockHeaders();
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		PublisherProbe<Void> publisherProbe = PublisherProbe.empty();
		given(this.authorizationFailureHandler.onAuthorizationFailure(any(), any(), any()))
				.willReturn(publisherProbe.mono());
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		// @formatter:on
		given(this.exchange.getResponse().rawStatusCode()).willReturn(HttpStatus.FORBIDDEN.value());
		this.function.filter(request, this.exchange).contextWrite(serverWebExchange()).block();
		assertThat(publisherProbe.wasSubscribed()).isTrue();
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		assertThat(this.authorizationExceptionCaptor.getValue())
				.isInstanceOfSatisfying(ClientAuthorizationException.class, (ex) -> {
					assertThat(ex.getClientRegistrationId()).isEqualTo(this.registration.getRegistrationId());
					assertThat(ex.getError().getErrorCode()).isEqualTo("insufficient_scope");
					assertThat(ex).hasNoCause();
					assertThat(ex).hasMessageContaining("[insufficient_scope]");
				});
		assertThat(this.authenticationCaptor.getValue()).isInstanceOf(AnonymousAuthenticationToken.class);
		assertThat(this.attributesCaptor.getValue())
				.containsExactly(entry(ServerWebExchange.class.getName(), this.serverWebExchange));
	}

	@Test
	public void filterWhenForbiddenWithWebClientExceptionThenInvokeFailureHandler() {
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		PublisherProbe<Void> publisherProbe = PublisherProbe.empty();
		given(this.authorizationFailureHandler.onAuthorizationFailure(any(), any(), any()))
				.willReturn(publisherProbe.mono());
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		WebClientResponseException exception = WebClientResponseException.create(HttpStatus.FORBIDDEN.value(),
				HttpStatus.FORBIDDEN.getReasonPhrase(), HttpHeaders.EMPTY, new byte[0], StandardCharsets.UTF_8);
		ExchangeFunction throwingExchangeFunction = (r) -> Mono.error(exception);
		// @formatter:off
		assertThatExceptionOfType(WebClientResponseException.class)
				.isThrownBy(() -> this.function
					.filter(request, throwingExchangeFunction)
					.contextWrite(serverWebExchange())
					.block()
				)
				.isEqualTo(exception);
		// @formatter:on
		assertThat(publisherProbe.wasSubscribed()).isTrue();
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		assertThat(this.authorizationExceptionCaptor.getValue())
				.isInstanceOfSatisfying(ClientAuthorizationException.class, (ex) -> {
					assertThat(ex.getClientRegistrationId()).isEqualTo(this.registration.getRegistrationId());
					assertThat(ex.getError().getErrorCode()).isEqualTo("insufficient_scope");
					assertThat(ex).hasCause(exception);
					assertThat(ex).hasMessageContaining("[insufficient_scope]");
				});
		assertThat(this.authenticationCaptor.getValue()).isInstanceOf(AnonymousAuthenticationToken.class);
		assertThat(this.attributesCaptor.getValue())
				.containsExactly(entry(ServerWebExchange.class.getName(), this.serverWebExchange));
	}

	@Test
	public void filterWhenWWWAuthenticateHeaderIncludesErrorThenInvokeFailureHandler() {
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		PublisherProbe<Void> publisherProbe = PublisherProbe.empty();
		given(this.authorizationFailureHandler.onAuthorizationFailure(any(), any(), any()))
				.willReturn(publisherProbe.mono());
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		String wwwAuthenticateHeader = "Bearer error=\"insufficient_scope\", "
				+ "error_description=\"The request requires higher privileges than provided by the access token.\", "
				+ "error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"";
		ClientResponse.Headers headers = mock(ClientResponse.Headers.class);
		given(headers.header(eq(HttpHeaders.WWW_AUTHENTICATE)))
				.willReturn(Collections.singletonList(wwwAuthenticateHeader));
		given(this.exchange.getResponse().headers()).willReturn(headers);
		this.function.filter(request, this.exchange).contextWrite(serverWebExchange()).block();
		assertThat(publisherProbe.wasSubscribed()).isTrue();
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		assertThat(this.authorizationExceptionCaptor.getValue())
				.isInstanceOfSatisfying(ClientAuthorizationException.class, (ex) -> {
					assertThat(ex.getClientRegistrationId()).isEqualTo(this.registration.getRegistrationId());
					assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
					assertThat(ex.getError().getDescription())
							.isEqualTo("The request requires higher privileges than provided by the access token.");
					assertThat(ex.getError().getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
					assertThat(ex).hasNoCause();
					assertThat(ex).hasMessageContaining(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
				});
		assertThat(this.authenticationCaptor.getValue()).isInstanceOf(AnonymousAuthenticationToken.class);
		assertThat(this.attributesCaptor.getValue())
				.containsExactly(entry(ServerWebExchange.class.getName(), this.serverWebExchange));
	}

	@Test
	public void filterWhenAuthorizationExceptionThenInvokeFailureHandler() {
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		PublisherProbe<Void> publisherProbe = PublisherProbe.empty();
		given(this.authorizationFailureHandler.onAuthorizationFailure(any(), any(), any()))
				.willReturn(publisherProbe.mono());
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		OAuth2AuthorizationException exception = new OAuth2AuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, null, null));
		ExchangeFunction throwingExchangeFunction = (r) -> Mono.error(exception);
		assertThatExceptionOfType(OAuth2AuthorizationException.class).isThrownBy(
				() -> this.function.filter(request, throwingExchangeFunction).contextWrite(serverWebExchange()).block())
				.isEqualTo(exception);
		assertThat(publisherProbe.wasSubscribed()).isTrue();
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		assertThat(this.authorizationExceptionCaptor.getValue()).isSameAs(exception);
		assertThat(this.authenticationCaptor.getValue()).isInstanceOf(AnonymousAuthenticationToken.class);
		assertThat(this.attributesCaptor.getValue())
				.containsExactly(entry(ServerWebExchange.class.getName(), this.serverWebExchange));
	}

	@Test
	public void filterWhenOtherHttpStatusShouldNotInvokeFailureHandler() {
		setupMockHeaders();
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
				.build();
		given(this.exchange.getResponse().rawStatusCode()).willReturn(HttpStatus.BAD_REQUEST.value());
		this.function.filter(request, this.exchange).contextWrite(serverWebExchange()).block();
		verify(this.authorizationFailureHandler, never()).onAuthorizationFailure(any(), any(), any());
	}

	@Test
	public void filterWhenPasswordClientNotAuthorizedThenGetNewToken() {
		setupMocks();
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("test", "this");
		ClientRegistration registration = TestClientRegistrations.password().build();
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("new-token")
				.tokenType(OAuth2AccessToken.TokenType.BEARER).expiresIn(360).build();
		given(this.passwordTokenResponseClient.getTokenResponse(any())).willReturn(Mono.just(accessTokenResponse));
		given(this.clientRegistrationRepository.findByRegistrationId(eq(registration.getRegistrationId())))
				.willReturn(Mono.just(registration));
		given(this.authorizedClientRepository.loadAuthorizedClient(eq(registration.getRegistrationId()),
				eq(authentication), any())).willReturn(Mono.empty());
		// Set custom contextAttributesMapper capable of mapping the form parameters
		this.authorizedClientManager.setContextAttributesMapper((authorizeRequest) -> {
			ServerWebExchange serverWebExchange = authorizeRequest.getAttribute(ServerWebExchange.class.getName());
			return Mono.just(serverWebExchange).flatMap(ServerWebExchange::getFormData).map((formData) -> {
				Map<String, Object> contextAttributes = new HashMap<>();
				String username = formData.getFirst(OAuth2ParameterNames.USERNAME);
				String password = formData.getFirst(OAuth2ParameterNames.PASSWORD);
				if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
					contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
					contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
				}
				return contextAttributes;
			});
		});
		this.serverWebExchange = MockServerWebExchange.builder(MockServerHttpRequest.post("/")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).body("username=username&password=password"))
				.build();
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction
						.clientRegistrationId(registration.getRegistrationId()))
				.build();
		this.function.filter(request, this.exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.contextWrite(serverWebExchange()).block();
		verify(this.passwordTokenResponseClient).getTokenResponse(any());
		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), eq(authentication), any());
		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		ClientRequest request1 = requests.get(0);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer new-token");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenClientRegistrationIdThenAuthorizedClientResolved() {
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		given(this.authorizedClientRepository.loadAuthorizedClient(any(), any(), any()))
				.willReturn(Mono.just(authorizedClient));
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction
						.clientRegistrationId(this.registration.getRegistrationId()))
				.build();
		this.function.filter(request, this.exchange).contextWrite(serverWebExchange()).block();
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
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		given(this.authorizedClientRepository.loadAuthorizedClient(any(), any(), any()))
				.willReturn(Mono.just(authorizedClient));
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com")).build();
		this.function.filter(request, this.exchange).contextWrite(serverWebExchange()).block();
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
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		given(this.authorizedClientRepository.loadAuthorizedClient(any(), any(), any()))
				.willReturn(Mono.just(authorizedClient));
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com")).build();
		OAuth2User user = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"),
				Collections.singletonMap("user", "rob"), "user");
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(user, user.getAuthorities(),
				"client-id");
		this.function.filter(request, this.exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.contextWrite(serverWebExchange()).block();
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
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com")).build();
		OAuth2User user = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"),
				Collections.singletonMap("user", "rob"), "user");
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(user, user.getAuthorities(),
				"client-id");
		// @formatter:off
		this.function.filter(request, this.exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();
		// @formatter:on
		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		verifyNoMoreInteractions(this.clientRegistrationRepository, this.authorizedClientRepository);
	}

	@Test
	public void filterWhenClientRegistrationIdAndServerWebExchangeFromContextThenServerWebExchangeFromContext() {
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		given(this.authorizedClientRepository.loadAuthorizedClient(any(), any(), any()))
				.willReturn(Mono.just(authorizedClient));
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId(this.registration.getRegistrationId()))
				.build();
		this.function.filter(request, this.exchange)
				.contextWrite(serverWebExchange())
				.block();
		// @formatter:on
		verify(this.authorizedClientRepository).loadAuthorizedClient(eq(this.registration.getRegistrationId()), any(),
				eq(this.serverWebExchange));
	}

	// gh-7544
	@Test
	public void filterWhenClientCredentialsClientNotAuthorizedAndOutsideRequestContextThenGetNewToken() {
		setupMockHeaders();
		ReactiveOAuth2AuthorizedClientService authorizedClientServiceDelegate = new InMemoryReactiveOAuth2AuthorizedClientService(
				this.clientRegistrationRepository);
		ReactiveOAuth2AuthorizedClientService authorizedClientService = new ReactiveOAuth2AuthorizedClientService() {
			@Override
			public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(String clientRegistrationId,
					String principalName) {
				return authorizedClientServiceDelegate.loadAuthorizedClient(clientRegistrationId, principalName);
			}

			@Override
			public Mono<Void> saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
				return authorizedClientServiceDelegate.saveAuthorizedClient(authorizedClient, principal);
			}

			@Override
			public Mono<Void> removeAuthorizedClient(String clientRegistrationId, String principalName) {
				return authorizedClientServiceDelegate.removeAuthorizedClient(clientRegistrationId, principalName);
			}
		};
		authorizedClientService = spy(authorizedClientService);
		AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, authorizedClientService);
		ClientCredentialsReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = new ClientCredentialsReactiveOAuth2AuthorizedClientProvider();
		authorizedClientProvider.setAccessTokenResponseClient(this.clientCredentialsTokenResponseClient);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
		this.function = new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("new-token")
				.tokenType(OAuth2AccessToken.TokenType.BEARER).expiresIn(360).build();
		given(this.clientCredentialsTokenResponseClient.getTokenResponse(any()))
				.willReturn(Mono.just(accessTokenResponse));
		ClientRegistration registration = TestClientRegistrations.clientCredentials().build();
		given(this.clientRegistrationRepository.findByRegistrationId(eq(registration.getRegistrationId())))
				.willReturn(Mono.just(registration));
		// @formatter:off
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.attributes(ServerOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId(registration.getRegistrationId()))
				.build();
		// @formatter:on
		this.function.filter(request, this.exchange).block();
		verify(authorizedClientService).loadAuthorizedClient(any(), any());
		verify(this.clientCredentialsTokenResponseClient).getTokenResponse(any());
		verify(authorizedClientService).saveAuthorizedClient(any(), any());
		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		ClientRequest request1 = requests.get(0);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer new-token");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
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
