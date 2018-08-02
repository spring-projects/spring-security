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

package org.springframework.security.config.web.server;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.config.EnableWebFlux;
import reactor.core.publisher.Mono;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
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
				.oauth2()
					.client();
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
}
