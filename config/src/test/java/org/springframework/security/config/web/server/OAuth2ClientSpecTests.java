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

package org.springframework.security.config.web.server;

import java.net.URI;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @author Parikshit Dutta
 * @since 5.1
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class OAuth2ClientSpecTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	private WebTestClient client;

	private ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		// @formatter:off
		this.client = WebTestClient
				.bindToApplicationContext(context)
				.build();
		// @formatter:on
	}

	@Test
	@WithMockUser
	public void registeredOAuth2AuthorizedClientWhenAuthenticatedThenRedirects() {
		this.spring.register(Config.class, AuthorizedClientController.class).autowire();
		ReactiveClientRegistrationRepository repository = this.spring.getContext()
			.getBean(ReactiveClientRegistrationRepository.class);
		ServerOAuth2AuthorizedClientRepository authorizedClientRepository = this.spring.getContext()
			.getBean(ServerOAuth2AuthorizedClientRepository.class);
		given(repository.findByRegistrationId(any()))
			.willReturn(Mono.just(TestClientRegistrations.clientRegistration().build()));
		given(authorizedClientRepository.loadAuthorizedClient(any(), any(), any())).willReturn(Mono.empty());
		// @formatter:off
		this.client.get()
				.uri("/")
				.exchange()
				.expectStatus().is3xxRedirection();
		// @formatter:on
	}

	@Test
	public void registeredOAuth2AuthorizedClientWhenAnonymousThenRedirects() {
		this.spring.register(Config.class, AuthorizedClientController.class).autowire();
		ReactiveClientRegistrationRepository repository = this.spring.getContext()
			.getBean(ReactiveClientRegistrationRepository.class);
		ServerOAuth2AuthorizedClientRepository authorizedClientRepository = this.spring.getContext()
			.getBean(ServerOAuth2AuthorizedClientRepository.class);
		given(repository.findByRegistrationId(any()))
			.willReturn(Mono.just(TestClientRegistrations.clientRegistration().build()));
		given(authorizedClientRepository.loadAuthorizedClient(any(), any(), any())).willReturn(Mono.empty());
		// @formatter:off
		this.client.get()
				.uri("/")
				.exchange()
				.expectStatus().is3xxRedirection();
		// @formatter:on
	}

	@Test
	public void oauth2ClientWhenCustomObjectsThenUsed() {
		this.spring
			.register(ClientRegistrationConfig.class, OAuth2ClientCustomConfig.class, AuthorizedClientController.class)
			.autowire();
		OAuth2ClientCustomConfig config = this.spring.getContext().getBean(OAuth2ClientCustomConfig.class);
		ServerAuthenticationConverter converter = config.authenticationConverter;
		ReactiveAuthenticationManager manager = config.manager;
		ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = config.authorizationRequestRepository;
		ServerOAuth2AuthorizationRequestResolver resolver = config.resolver;
		ServerRequestCache requestCache = config.requestCache;
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
			.redirectUri("/authorize/oauth2/code/registration-id")
			.build();
		OAuth2AuthorizationResponse authorizationResponse = TestOAuth2AuthorizationResponses.success()
			.redirectUri("/authorize/oauth2/code/registration-id")
			.build();
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(authorizationRequest,
				authorizationResponse);
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.noScopes();
		OAuth2AuthorizationCodeAuthenticationToken result = new OAuth2AuthorizationCodeAuthenticationToken(
				this.registration, authorizationExchange, accessToken);
		given(authorizationRequestRepository.loadAuthorizationRequest(any()))
			.willReturn(Mono.just(authorizationRequest));
		given(resolver.resolve(any())).willReturn(Mono.empty());
		given(converter.convert(any())).willReturn(Mono.just(new TestingAuthenticationToken("a", "b", "c")));
		given(manager.authenticate(any())).willReturn(Mono.just(result));
		given(requestCache.getRedirectUri(any())).willReturn(Mono.just(URI.create("/saved-request")));
		// @formatter:off
		this.client.get()
				.uri((uriBuilder) -> uriBuilder
						.path("/authorize/oauth2/code/registration-id")
						.queryParam(OAuth2ParameterNames.CODE, "code")
						.queryParam(OAuth2ParameterNames.STATE, "state")
						.build()
				)
				.exchange()
				.expectStatus().is3xxRedirection();
		// @formatter:on
		verify(converter).convert(any());
		verify(manager).authenticate(any());
		verify(requestCache).getRedirectUri(any());
		verify(resolver).resolve(any());
	}

	@Test
	public void oauth2ClientWhenCustomObjectsInLambdaThenUsed() {
		this.spring
			.register(ClientRegistrationConfig.class, OAuth2ClientInLambdaCustomConfig.class,
					AuthorizedClientController.class)
			.autowire();
		OAuth2ClientInLambdaCustomConfig config = this.spring.getContext()
			.getBean(OAuth2ClientInLambdaCustomConfig.class);
		ServerAuthenticationConverter converter = config.authenticationConverter;
		ReactiveAuthenticationManager manager = config.manager;
		ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = config.authorizationRequestRepository;
		ServerRequestCache requestCache = config.requestCache;
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
			.redirectUri("/authorize/oauth2/code/registration-id")
			.build();
		OAuth2AuthorizationResponse authorizationResponse = TestOAuth2AuthorizationResponses.success()
			.redirectUri("/authorize/oauth2/code/registration-id")
			.build();
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(authorizationRequest,
				authorizationResponse);
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.noScopes();
		OAuth2AuthorizationCodeAuthenticationToken result = new OAuth2AuthorizationCodeAuthenticationToken(
				this.registration, authorizationExchange, accessToken);
		given(authorizationRequestRepository.loadAuthorizationRequest(any()))
			.willReturn(Mono.just(authorizationRequest));
		given(converter.convert(any())).willReturn(Mono.just(new TestingAuthenticationToken("a", "b", "c")));
		given(manager.authenticate(any())).willReturn(Mono.just(result));
		given(requestCache.getRedirectUri(any())).willReturn(Mono.just(URI.create("/saved-request")));
		// @formatter:off
		this.client.get()
				.uri((uriBuilder) -> uriBuilder
						.path("/authorize/oauth2/code/registration-id")
						.queryParam(OAuth2ParameterNames.CODE, "code")
						.queryParam(OAuth2ParameterNames.STATE, "state")
						.build()
				)
				.exchange()
				.expectStatus().is3xxRedirection();
		// @formatter:on
		verify(converter).convert(any());
		verify(manager).authenticate(any());
		verify(requestCache).getRedirectUri(any());
	}

	@Test
	@SuppressWarnings("unchecked")
	public void oauth2ClientWhenCustomAccessTokenResponseClientThenUsed() {
		this.spring.register(OAuth2ClientBeanConfig.class, AuthorizedClientController.class).autowire();
		ReactiveClientRegistrationRepository clientRegistrationRepository = this.spring.getContext()
			.getBean(ReactiveClientRegistrationRepository.class);
		given(clientRegistrationRepository.findByRegistrationId(any())).willReturn(Mono.just(this.registration));
		ServerOAuth2AuthorizedClientRepository authorizedClientRepository = this.spring.getContext()
			.getBean(ServerOAuth2AuthorizedClientRepository.class);
		given(authorizedClientRepository.saveAuthorizedClient(any(OAuth2AuthorizedClient.class),
				any(Authentication.class), any(ServerWebExchange.class)))
			.willReturn(Mono.empty());
		ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = this.spring
			.getContext()
			.getBean(ServerAuthorizationRequestRepository.class);
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request()
			.redirectUri("/authorize/oauth2/code/registration-id")
			.build();
		given(authorizationRequestRepository.loadAuthorizationRequest(any(ServerWebExchange.class)))
			.willReturn(Mono.just(authorizationRequest));
		given(authorizationRequestRepository.removeAuthorizationRequest(any(ServerWebExchange.class)))
			.willReturn(Mono.just(authorizationRequest));
		ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient = this.spring
			.getContext()
			.getBean(ReactiveOAuth2AccessTokenResponseClient.class);
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("token")
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.scopes(Set.of())
			.expiresIn(300)
			.build();
		given(accessTokenResponseClient.getTokenResponse(any(OAuth2AuthorizationCodeGrantRequest.class)))
			.willReturn(Mono.just(accessTokenResponse));
		// @formatter:off
		this.client.get()
			.uri((uriBuilder) -> uriBuilder
				.path("/authorize/oauth2/code/registration-id")
				.queryParam(OAuth2ParameterNames.CODE, "code")
				.queryParam(OAuth2ParameterNames.STATE, "state")
				.build()
			)
			.exchange()
			.expectStatus().is3xxRedirection();
		// @formatter:on
		ArgumentCaptor<OAuth2AuthorizationCodeGrantRequest> grantRequestArgumentCaptor = ArgumentCaptor
			.forClass(OAuth2AuthorizationCodeGrantRequest.class);
		verify(accessTokenResponseClient).getTokenResponse(grantRequestArgumentCaptor.capture());
		OAuth2AuthorizationCodeGrantRequest grantRequest = grantRequestArgumentCaptor.getValue();
		assertThat(grantRequest.getClientRegistration()).isEqualTo(this.registration);
		assertThat(grantRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(grantRequest.getAuthorizationExchange().getAuthorizationRequest()).isEqualTo(authorizationRequest);
		assertThat(grantRequest.getAuthorizationExchange().getAuthorizationResponse().getCode()).isEqualTo("code");
		assertThat(grantRequest.getAuthorizationExchange().getAuthorizationResponse().getState()).isEqualTo("state");
		assertThat(grantRequest.getAuthorizationExchange().getAuthorizationResponse().getRedirectUri())
			.startsWith("/authorize/oauth2/code/registration-id");
	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class Config {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.oauth2Client();
			// @formatter:on
			return http.build();
		}

		@Bean
		ReactiveClientRegistrationRepository clientRegistrationRepository() {
			return mock(ReactiveClientRegistrationRepository.class);
		}

		@Bean
		ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
			return mock(ServerOAuth2AuthorizedClientRepository.class);
		}

	}

	@RestController
	static class AuthorizedClientController {

		@GetMapping("/")
		String home(@RegisteredOAuth2AuthorizedClient("github") OAuth2AuthorizedClient authorizedClient) {
			return "home";
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class ClientRegistrationConfig {

		private ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();

		@Bean
		InMemoryReactiveClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryReactiveClientRegistrationRepository(this.clientRegistration);
		}

	}

	@Configuration
	static class OAuth2ClientCustomConfig {

		ReactiveAuthenticationManager manager = mock(ReactiveAuthenticationManager.class);

		ServerAuthenticationConverter authenticationConverter = mock(ServerAuthenticationConverter.class);

		ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = mock(
				ServerAuthorizationRequestRepository.class);

		ServerOAuth2AuthorizationRequestResolver resolver = mock(ServerOAuth2AuthorizationRequestResolver.class);

		ServerRequestCache requestCache = mock(ServerRequestCache.class);

		@Bean
		SecurityWebFilterChain springSecurityFilter(ServerHttpSecurity http) {
			// @formatter:off
			http
				.oauth2Client()
					.authenticationConverter(this.authenticationConverter)
					.authenticationManager(this.manager)
					.authorizationRequestRepository(this.authorizationRequestRepository)
					.authorizationRequestResolver(this.resolver)
					.and()
				.requestCache((c) -> c.requestCache(this.requestCache));
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	static class OAuth2ClientInLambdaCustomConfig {

		ReactiveAuthenticationManager manager = mock(ReactiveAuthenticationManager.class);

		ServerAuthenticationConverter authenticationConverter = mock(ServerAuthenticationConverter.class);

		ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = mock(
				ServerAuthorizationRequestRepository.class);

		ServerRequestCache requestCache = mock(ServerRequestCache.class);

		@Bean
		SecurityWebFilterChain springSecurityFilter(ServerHttpSecurity http) {
			// @formatter:off
			http
				.oauth2Client((oauth2Client) ->
					oauth2Client
						.authenticationConverter(this.authenticationConverter)
						.authenticationManager(this.manager)
						.authorizationRequestRepository(this.authorizationRequestRepository))
				.requestCache((c) -> c.requestCache(this.requestCache));
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class OAuth2ClientBeanConfig {

		@Bean
		SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
			// @formatter:off
			http
				.oauth2Client((oauth2Client) -> oauth2Client
					.authorizationRequestRepository(authorizationRequestRepository())
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		@SuppressWarnings("unchecked")
		ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
			return mock(ServerAuthorizationRequestRepository.class);
		}

		@Bean
		@SuppressWarnings("unchecked")
		ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeAccessTokenResponseClient() {
			return mock(ReactiveOAuth2AccessTokenResponseClient.class);
		}

		@Bean
		ReactiveClientRegistrationRepository clientRegistrationRepository() {
			return mock(ReactiveClientRegistrationRepository.class);
		}

		@Bean
		ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
			return mock(ServerOAuth2AuthorizedClientRepository.class);
		}

	}

}
