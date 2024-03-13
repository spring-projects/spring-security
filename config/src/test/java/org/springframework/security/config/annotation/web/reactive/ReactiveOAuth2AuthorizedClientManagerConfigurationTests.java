/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.web.reactive;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.oauth2.client.AuthorizationCodeReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.JwtBearerReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.PasswordReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.RefreshTokenReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.TokenExchangeReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.endpoint.JwtBearerGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests for
 * {@link ReactiveOAuth2ClientConfiguration.ReactiveOAuth2AuthorizedClientManagerConfiguration}.
 *
 * @author Steve Riesenberg
 */
public class ReactiveOAuth2AuthorizedClientManagerConfigurationTests {

	private static ReactiveOAuth2AccessTokenResponseClient<? super AbstractOAuth2AuthorizationGrantRequest> MOCK_RESPONSE_CLIENT;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

	@Autowired
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	@Autowired(required = false)
	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	@Autowired(required = false)
	private ReactiveOAuth2AuthorizedClientService authorizedClientService;

	@Autowired(required = false)
	private AuthorizationCodeReactiveOAuth2AuthorizedClientProvider authorizationCodeAuthorizedClientProvider;

	private MockServerWebExchange exchange;

	@BeforeEach
	@SuppressWarnings("unchecked")
	public void setUp() {
		MOCK_RESPONSE_CLIENT = mock(ReactiveOAuth2AccessTokenResponseClient.class);
		MockServerHttpRequest request = MockServerHttpRequest.get("/").build();
		this.exchange = MockServerWebExchange.builder(request).build();
	}

	@Test
	public void loadContextWhenOAuth2ClientEnabledThenConfigured() {
		this.spring.register(MinimalOAuth2ClientConfig.class).autowire();
		assertThat(this.authorizedClientManager).isNotNull();
	}

	@Test
	public void authorizeWhenAuthorizationCodeAuthorizedClientProviderBeanThenUsed() {
		this.spring.register(CustomAuthorizedClientProvidersConfig.class).autowire();

		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", null, "ROLE_USER");
		// @formatter:off
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId("google")
				.principal(authentication)
				.attribute(ServerWebExchange.class.getName(), this.exchange)
				.build();
		assertThatExceptionOfType(ClientAuthorizationRequiredException.class)
				.isThrownBy(() -> this.authorizedClientManager.authorize(authorizeRequest).block())
				.extracting(OAuth2AuthorizationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo("client_authorization_required");
		// @formatter:on

		verify(this.authorizationCodeAuthorizedClientProvider).authorize(any(OAuth2AuthorizationContext.class));
	}

	@Test
	public void authorizeWhenAuthorizedClientServiceBeanThenUsed() {
		this.spring.register(CustomAuthorizedClientServiceConfig.class).autowire();

		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", null, "ROLE_USER");
		// @formatter:off
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId("google")
				.principal(authentication)
				.attribute(ServerWebExchange.class.getName(), this.exchange)
				.build();
		assertThatExceptionOfType(ClientAuthorizationRequiredException.class)
				.isThrownBy(() -> this.authorizedClientManager.authorize(authorizeRequest).block())
				.extracting(OAuth2AuthorizationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo("client_authorization_required");
		// @formatter:on

		verify(this.authorizedClientService).loadAuthorizedClient(authorizeRequest.getClientRegistrationId(),
				authentication.getName());
	}

	@Test
	public void authorizeWhenRefreshTokenAccessTokenResponseClientBeanThenUsed() {
		this.spring.register(CustomAccessTokenResponseClientsConfig.class).autowire();
		testRefreshTokenGrant();
	}

	@Test
	public void authorizeWhenRefreshTokenAuthorizedClientProviderBeanThenUsed() {
		this.spring.register(CustomAuthorizedClientProvidersConfig.class).autowire();
		testRefreshTokenGrant();
	}

	private void testRefreshTokenGrant() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(MOCK_RESPONSE_CLIENT.getTokenResponse(any(OAuth2RefreshTokenGrantRequest.class)))
			.willReturn(Mono.just(accessTokenResponse));

		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", null, "ROLE_USER");
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("google")
			.block();
		assertThat(clientRegistration).isNotNull();
		OAuth2AuthorizedClient existingAuthorizedClient = new OAuth2AuthorizedClient(clientRegistration,
				authentication.getName(), getExpiredAccessToken(), TestOAuth2RefreshTokens.refreshToken());
		this.authorizedClientRepository.saveAuthorizedClient(existingAuthorizedClient, authentication, this.exchange)
			.block();
		// @formatter:off
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(clientRegistration.getRegistrationId())
				.principal(authentication)
				.attribute(ServerWebExchange.class.getName(), this.exchange)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest).block();
		assertThat(authorizedClient).isNotNull();

		ArgumentCaptor<OAuth2RefreshTokenGrantRequest> grantRequestCaptor = ArgumentCaptor
			.forClass(OAuth2RefreshTokenGrantRequest.class);
		verify(MOCK_RESPONSE_CLIENT).getTokenResponse(grantRequestCaptor.capture());

		OAuth2RefreshTokenGrantRequest grantRequest = grantRequestCaptor.getValue();
		assertThat(grantRequest.getClientRegistration().getRegistrationId())
			.isEqualTo(clientRegistration.getRegistrationId());
		assertThat(grantRequest.getGrantType()).isEqualTo(AuthorizationGrantType.REFRESH_TOKEN);
		assertThat(grantRequest.getAccessToken()).isEqualTo(existingAuthorizedClient.getAccessToken());
		assertThat(grantRequest.getRefreshToken()).isEqualTo(existingAuthorizedClient.getRefreshToken());
	}

	@Test
	public void authorizeWhenClientCredentialsAccessTokenResponseClientBeanThenUsed() {
		this.spring.register(CustomAccessTokenResponseClientsConfig.class).autowire();
		testClientCredentialsGrant();
	}

	@Test
	public void authorizeWhenClientCredentialsAuthorizedClientProviderBeanThenUsed() {
		this.spring.register(CustomAuthorizedClientProvidersConfig.class).autowire();
		testClientCredentialsGrant();
	}

	private void testClientCredentialsGrant() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(MOCK_RESPONSE_CLIENT.getTokenResponse(any(OAuth2ClientCredentialsGrantRequest.class)))
			.willReturn(Mono.just(accessTokenResponse));

		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", null, "ROLE_USER");
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("github")
			.block();
		assertThat(clientRegistration).isNotNull();
		// @formatter:off
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(clientRegistration.getRegistrationId())
				.principal(authentication)
				.attribute(ServerWebExchange.class.getName(), this.exchange)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest).block();
		assertThat(authorizedClient).isNotNull();

		ArgumentCaptor<OAuth2ClientCredentialsGrantRequest> grantRequestCaptor = ArgumentCaptor
			.forClass(OAuth2ClientCredentialsGrantRequest.class);
		verify(MOCK_RESPONSE_CLIENT).getTokenResponse(grantRequestCaptor.capture());

		OAuth2ClientCredentialsGrantRequest grantRequest = grantRequestCaptor.getValue();
		assertThat(grantRequest.getClientRegistration().getRegistrationId())
			.isEqualTo(clientRegistration.getRegistrationId());
		assertThat(grantRequest.getGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
	}

	@Test
	public void authorizeWhenPasswordAccessTokenResponseClientBeanThenUsed() {
		this.spring.register(CustomAccessTokenResponseClientsConfig.class).autowire();
		testPasswordGrant();
	}

	@Test
	public void authorizeWhenPasswordAuthorizedClientProviderBeanThenUsed() {
		this.spring.register(CustomAuthorizedClientProvidersConfig.class).autowire();
		testPasswordGrant();
	}

	private void testPasswordGrant() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(MOCK_RESPONSE_CLIENT.getTokenResponse(any(OAuth2PasswordGrantRequest.class)))
			.willReturn(Mono.just(accessTokenResponse));

		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("facebook")
			.block();
		assertThat(clientRegistration).isNotNull();
		MockServerHttpRequest request = MockServerHttpRequest.post("/")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.body("username=user&password=password");
		this.exchange = MockServerWebExchange.builder(request).build();
		// @formatter:off
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(clientRegistration.getRegistrationId())
				.principal(authentication)
				.attribute(ServerWebExchange.class.getName(), this.exchange)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest).block();
		assertThat(authorizedClient).isNotNull();

		ArgumentCaptor<OAuth2PasswordGrantRequest> grantRequestCaptor = ArgumentCaptor
			.forClass(OAuth2PasswordGrantRequest.class);
		verify(MOCK_RESPONSE_CLIENT).getTokenResponse(grantRequestCaptor.capture());

		OAuth2PasswordGrantRequest grantRequest = grantRequestCaptor.getValue();
		assertThat(grantRequest.getClientRegistration().getRegistrationId())
			.isEqualTo(clientRegistration.getRegistrationId());
		assertThat(grantRequest.getGrantType()).isEqualTo(AuthorizationGrantType.PASSWORD);
		assertThat(grantRequest.getUsername()).isEqualTo("user");
		assertThat(grantRequest.getPassword()).isEqualTo("password");
	}

	@Test
	public void authorizeWhenJwtBearerAccessTokenResponseClientBeanThenUsed() {
		this.spring.register(CustomAccessTokenResponseClientsConfig.class).autowire();
		testJwtBearerGrant();
	}

	@Test
	public void authorizeWhenJwtBearerAuthorizedClientProviderBeanThenUsed() {
		this.spring.register(CustomAuthorizedClientProvidersConfig.class).autowire();
		testJwtBearerGrant();
	}

	private void testJwtBearerGrant() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(MOCK_RESPONSE_CLIENT.getTokenResponse(any(JwtBearerGrantRequest.class)))
			.willReturn(Mono.just(accessTokenResponse));

		JwtAuthenticationToken authentication = new JwtAuthenticationToken(getJwt());
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("okta").block();
		assertThat(clientRegistration).isNotNull();
		// @formatter:off
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(clientRegistration.getRegistrationId())
				.principal(authentication)
				.attribute(ServerWebExchange.class.getName(), this.exchange)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest).block();
		assertThat(authorizedClient).isNotNull();

		ArgumentCaptor<JwtBearerGrantRequest> grantRequestCaptor = ArgumentCaptor.forClass(JwtBearerGrantRequest.class);
		verify(MOCK_RESPONSE_CLIENT).getTokenResponse(grantRequestCaptor.capture());

		JwtBearerGrantRequest grantRequest = grantRequestCaptor.getValue();
		assertThat(grantRequest.getClientRegistration().getRegistrationId())
			.isEqualTo(clientRegistration.getRegistrationId());
		assertThat(grantRequest.getGrantType()).isEqualTo(AuthorizationGrantType.JWT_BEARER);
		assertThat(grantRequest.getJwt().getSubject()).isEqualTo("user");
	}

	@Test
	public void authorizeWhenTokenExchangeAccessTokenResponseClientBeanThenUsed() {
		this.spring.register(CustomAccessTokenResponseClientsConfig.class).autowire();
		testTokenExchangeGrant();
	}

	@Test
	public void authorizeWhenTokenExchangeAuthorizedClientProviderBeanThenUsed() {
		this.spring.register(CustomAuthorizedClientProvidersConfig.class).autowire();
		testTokenExchangeGrant();
	}

	private void testTokenExchangeGrant() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(MOCK_RESPONSE_CLIENT.getTokenResponse(any(TokenExchangeGrantRequest.class)))
			.willReturn(Mono.just(accessTokenResponse));

		JwtAuthenticationToken authentication = new JwtAuthenticationToken(getJwt());
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("auth0").block();
		assertThat(clientRegistration).isNotNull();
		// @formatter:off
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(clientRegistration.getRegistrationId())
				.principal(authentication)
				.attribute(ServerWebExchange.class.getName(), this.exchange)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest).block();
		assertThat(authorizedClient).isNotNull();

		ArgumentCaptor<TokenExchangeGrantRequest> grantRequestCaptor = ArgumentCaptor
			.forClass(TokenExchangeGrantRequest.class);
		verify(MOCK_RESPONSE_CLIENT).getTokenResponse(grantRequestCaptor.capture());

		TokenExchangeGrantRequest grantRequest = grantRequestCaptor.getValue();
		assertThat(grantRequest.getClientRegistration().getRegistrationId())
			.isEqualTo(clientRegistration.getRegistrationId());
		assertThat(grantRequest.getGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);
		assertThat(grantRequest.getSubjectToken()).isEqualTo(authentication.getToken());
	}

	private static OAuth2AccessToken getExpiredAccessToken() {
		Instant expiresAt = Instant.now().minusSeconds(60);
		Instant issuedAt = expiresAt.minus(Duration.ofDays(1));
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "scopes", issuedAt, expiresAt,
				new HashSet<>(Arrays.asList("read", "write")));
	}

	private static Jwt getJwt() {
		Instant issuedAt = Instant.now();
		return new Jwt("token", issuedAt, issuedAt.plusSeconds(300),
				Collections.singletonMap(JoseHeaderNames.ALG, "RS256"),
				Collections.singletonMap(JwtClaimNames.SUB, "user"));
	}

	@Configuration
	@EnableWebFluxSecurity
	static class MinimalOAuth2ClientConfig extends OAuth2ClientBaseConfig {

		@Bean
		ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
			return new WebSessionServerOAuth2AuthorizedClientRepository();
		}

	}

	@Configuration
	@EnableWebFluxSecurity
	static class CustomAuthorizedClientServiceConfig extends OAuth2ClientBaseConfig {

		@Bean
		ReactiveOAuth2AuthorizedClientService authorizedClientService() {
			ReactiveOAuth2AuthorizedClientService authorizedClientService = mock(
					ReactiveOAuth2AuthorizedClientService.class);
			given(authorizedClientService.loadAuthorizedClient(anyString(), anyString())).willReturn(Mono.empty());
			return authorizedClientService;
		}

	}

	@Configuration
	@EnableWebFluxSecurity
	static class CustomAccessTokenResponseClientsConfig extends MinimalOAuth2ClientConfig {

		@Bean
		ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeAccessTokenResponseClient() {
			return new MockAccessTokenResponseClient<>();
		}

		@Bean
		ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenTokenAccessResponseClient() {
			return new MockAccessTokenResponseClient<>();
		}

		@Bean
		ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsAccessTokenResponseClient() {
			return new MockAccessTokenResponseClient<>();
		}

		@Bean
		ReactiveOAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> passwordAccessTokenResponseClient() {
			return new MockAccessTokenResponseClient<>();
		}

		@Bean
		ReactiveOAuth2AccessTokenResponseClient<JwtBearerGrantRequest> jwtBearerAccessTokenResponseClient() {
			return new MockAccessTokenResponseClient<>();
		}

		@Bean
		ReactiveOAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> tokenExchangeAccessTokenResponseClient() {
			return new MockAccessTokenResponseClient<>();
		}

	}

	@Configuration
	@EnableWebFluxSecurity
	static class CustomAuthorizedClientProvidersConfig extends MinimalOAuth2ClientConfig {

		@Bean
		AuthorizationCodeReactiveOAuth2AuthorizedClientProvider authorizationCode() {
			return spy(new AuthorizationCodeReactiveOAuth2AuthorizedClientProvider());
		}

		@Bean
		RefreshTokenReactiveOAuth2AuthorizedClientProvider refreshToken() {
			RefreshTokenReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = new RefreshTokenReactiveOAuth2AuthorizedClientProvider();
			authorizedClientProvider.setAccessTokenResponseClient(new MockAccessTokenResponseClient<>());
			return authorizedClientProvider;
		}

		@Bean
		ClientCredentialsReactiveOAuth2AuthorizedClientProvider clientCredentials() {
			ClientCredentialsReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = new ClientCredentialsReactiveOAuth2AuthorizedClientProvider();
			authorizedClientProvider.setAccessTokenResponseClient(new MockAccessTokenResponseClient<>());
			return authorizedClientProvider;
		}

		@Bean
		PasswordReactiveOAuth2AuthorizedClientProvider password() {
			PasswordReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = new PasswordReactiveOAuth2AuthorizedClientProvider();
			authorizedClientProvider.setAccessTokenResponseClient(new MockAccessTokenResponseClient<>());
			return authorizedClientProvider;
		}

		@Bean
		JwtBearerReactiveOAuth2AuthorizedClientProvider jwtBearer() {
			JwtBearerReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = new JwtBearerReactiveOAuth2AuthorizedClientProvider();
			authorizedClientProvider.setAccessTokenResponseClient(new MockAccessTokenResponseClient<>());
			return authorizedClientProvider;
		}

		@Bean
		TokenExchangeReactiveOAuth2AuthorizedClientProvider tokenExchange() {
			TokenExchangeReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = new TokenExchangeReactiveOAuth2AuthorizedClientProvider();
			authorizedClientProvider.setAccessTokenResponseClient(new MockAccessTokenResponseClient<>());
			return authorizedClientProvider;
		}

	}

	abstract static class OAuth2ClientBaseConfig {

		@Bean
		ReactiveClientRegistrationRepository clientRegistrationRepository() {
			// @formatter:off
			return new InMemoryReactiveClientRegistrationRepository(
					CommonOAuth2Provider.GOOGLE.getBuilder("google")
						.clientId("google-client-id")
						.clientSecret("google-client-secret")
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.build(),
					CommonOAuth2Provider.GITHUB.getBuilder("github")
						.clientId("github-client-id")
						.clientSecret("github-client-secret")
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
						.build(),
					CommonOAuth2Provider.FACEBOOK.getBuilder("facebook")
						.clientId("facebook-client-id")
						.clientSecret("facebook-client-secret")
						.authorizationGrantType(AuthorizationGrantType.PASSWORD)
						.build(),
					CommonOAuth2Provider.OKTA.getBuilder("okta")
						.clientId("okta-client-id")
						.clientSecret("okta-client-secret")
						.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
						.build(),
					ClientRegistration.withRegistrationId("auth0")
						.clientName("Auth0")
						.clientId("auth0-client-id")
						.clientSecret("auth0-client-secret")
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
						.scope("user.read", "user.write")
						.build());
			// @formatter:on
		}

		@Bean
		Consumer<DefaultReactiveOAuth2AuthorizedClientManager> authorizedClientManagerConsumer() {
			return (authorizedClientManager) -> authorizedClientManager
				.setContextAttributesMapper((authorizeRequest) -> {
					ServerWebExchange exchange = Objects
						.requireNonNull(authorizeRequest.getAttribute(ServerWebExchange.class.getName()));
					return exchange.getFormData().map((parameters) -> {
						String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
						String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);

						Map<String, Object> attributes = Collections.emptyMap();
						if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
							attributes = new HashMap<>();
							attributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
							attributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
						}

						return attributes;
					});
				});

		}

	}

	private static class MockAccessTokenResponseClient<T extends AbstractOAuth2AuthorizationGrantRequest>
			implements ReactiveOAuth2AccessTokenResponseClient<T> {

		@Override
		public Mono<OAuth2AccessTokenResponse> getTokenResponse(T grantRequest) {
			return MOCK_RESPONSE_CLIENT.getTokenResponse(grantRequest);
		}

	}

}
