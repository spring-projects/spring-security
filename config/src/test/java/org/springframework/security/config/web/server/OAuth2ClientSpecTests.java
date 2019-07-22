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

package org.springframework.security.config.web.server;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationExchanges;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.config.EnableWebFlux;
import reactor.core.publisher.Mono;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(SpringRunner.class)
@SecurityTestExecutionListeners
public class OAuth2ClientSpecTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	private WebTestClient client;

	private ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.client = WebTestClient.bindToApplicationContext(context).build();
	}

	@Test
	@WithMockUser
	public void registeredOAuth2AuthorizedClientWhenAuthenticatedThenRedirects() {
		this.spring.register(Config.class, AuthorizedClientController.class).autowire();
		ReactiveClientRegistrationRepository repository = this.spring.getContext()
				.getBean(ReactiveClientRegistrationRepository.class);
		ServerOAuth2AuthorizedClientRepository authorizedClientRepository = this.spring.getContext().getBean(ServerOAuth2AuthorizedClientRepository.class);
		when(repository.findByRegistrationId(any())).thenReturn(Mono.just(TestClientRegistrations.clientRegistration().build()));
		when(authorizedClientRepository.loadAuthorizedClient(any(), any(), any())).thenReturn(Mono.empty());

		this.client.get().uri("/")
			.exchange()
			.expectStatus().is3xxRedirection();
	}

	@Test
	public void registeredOAuth2AuthorizedClientWhenAnonymousThenRedirects() {
		this.spring.register(Config.class, AuthorizedClientController.class).autowire();
		ReactiveClientRegistrationRepository repository = this.spring.getContext()
				.getBean(ReactiveClientRegistrationRepository.class);
		ServerOAuth2AuthorizedClientRepository authorizedClientRepository = this.spring.getContext().getBean(ServerOAuth2AuthorizedClientRepository.class);
		when(repository.findByRegistrationId(any())).thenReturn(Mono.just(TestClientRegistrations.clientRegistration().build()));
		when(authorizedClientRepository.loadAuthorizedClient(any(), any(), any())).thenReturn(Mono.empty());

		this.client.get().uri("/")
				.exchange()
				.expectStatus().is3xxRedirection();
	}

	@EnableWebFlux
	@EnableWebFluxSecurity
	static class Config {
		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			http
				.oauth2Client();
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

	@Test
	public void oauth2ClientWhenCustomObjectsThenUsed() {
		this.spring.register(ClientRegistrationConfig.class, OAuth2ClientCustomConfig.class, AuthorizedClientController.class).autowire();

		OAuth2ClientCustomConfig config = this.spring.getContext().getBean(OAuth2ClientCustomConfig.class);

		ServerAuthenticationConverter converter = config.authenticationConverter;
		ReactiveAuthenticationManager manager = config.manager;

		OAuth2AuthorizationExchange exchange = TestOAuth2AuthorizationExchanges.success();
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.noScopes();

		OAuth2AuthorizationCodeAuthenticationToken result = new OAuth2AuthorizationCodeAuthenticationToken(this.registration, exchange, accessToken);

		when(converter.convert(any())).thenReturn(Mono.just(new TestingAuthenticationToken("a", "b", "c")));
		when(manager.authenticate(any())).thenReturn(Mono.just(result));

		this.client.get()
			.uri("/authorize/oauth2/code/registration-id")
			.exchange()
			.expectStatus().is3xxRedirection();

		verify(converter).convert(any());
		verify(manager).authenticate(any());
	}

	@EnableWebFlux
	@EnableWebFluxSecurity
	static class ClientRegistrationConfig {
		private ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.build();

		@Bean
		InMemoryReactiveClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryReactiveClientRegistrationRepository(this.clientRegistration);
		}
	}

	@Configuration
	static class OAuth2ClientCustomConfig {
		ReactiveAuthenticationManager manager = mock(ReactiveAuthenticationManager.class);

		ServerAuthenticationConverter authenticationConverter = mock(ServerAuthenticationConverter.class);

		@Bean
		public SecurityWebFilterChain springSecurityFilter(ServerHttpSecurity http) {
			http
				.oauth2Client()
					.authenticationConverter(this.authenticationConverter)
					.authenticationManager(this.manager);
			return http.build();
		}
	}

	@Test
	public void oauth2ClientWhenCustomObjectsInLambdaThenUsed() {
		this.spring.register(ClientRegistrationConfig.class, OAuth2ClientInLambdaCustomConfig.class, AuthorizedClientController.class).autowire();

		OAuth2ClientInLambdaCustomConfig config = this.spring.getContext().getBean(OAuth2ClientInLambdaCustomConfig.class);

		ServerAuthenticationConverter converter = config.authenticationConverter;
		ReactiveAuthenticationManager manager = config.manager;

		OAuth2AuthorizationExchange exchange = TestOAuth2AuthorizationExchanges.success();
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.noScopes();

		OAuth2AuthorizationCodeAuthenticationToken result = new OAuth2AuthorizationCodeAuthenticationToken(this.registration, exchange, accessToken);

		when(converter.convert(any())).thenReturn(Mono.just(new TestingAuthenticationToken("a", "b", "c")));
		when(manager.authenticate(any())).thenReturn(Mono.just(result));

		this.client.get()
				.uri("/authorize/oauth2/code/registration-id")
				.exchange()
				.expectStatus().is3xxRedirection();

		verify(converter).convert(any());
		verify(manager).authenticate(any());
	}

	@Configuration
	static class OAuth2ClientInLambdaCustomConfig {
		ReactiveAuthenticationManager manager = mock(ReactiveAuthenticationManager.class);

		ServerAuthenticationConverter authenticationConverter = mock(ServerAuthenticationConverter.class);

		@Bean
		public SecurityWebFilterChain springSecurityFilter(ServerHttpSecurity http) throws Exception {
			http
				.oauth2Client(oauth2Client ->
					oauth2Client
						.authenticationConverter(this.authenticationConverter)
						.authenticationManager(this.manager)
				);
			return http.build();
		}
	}
}
