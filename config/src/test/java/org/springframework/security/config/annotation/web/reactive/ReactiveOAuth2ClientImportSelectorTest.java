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

package org.springframework.security.config.annotation.web.reactive;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.config.EnableWebFlux;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link ReactiveOAuth2ClientImportSelector}.
 *
 * @author Alavudin Kuttikkattil
 */
@ExtendWith(SpringTestContextExtension.class)
public class ReactiveOAuth2ClientImportSelectorTest {

	public final SpringTestContext spring = new SpringTestContext(this);

	WebTestClient client;

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		// @formatter:off
		this.client = WebTestClient
				.bindToApplicationContext(context)
				.build();
		// @formatter:on
	}

	@Test
	public void requestWhenAuthorizedClientManagerConfiguredThenUsed() {
		String clientRegistrationId = "client";
		String principalName = "user";
		ReactiveClientRegistrationRepository clientRegistrationRepository = mock(
				ReactiveClientRegistrationRepository.class);
		ServerOAuth2AuthorizedClientRepository authorizedClientRepository = mock(
				ServerOAuth2AuthorizedClientRepository.class);
		ReactiveOAuth2AuthorizedClientManager authorizedClientManager = mock(
				ReactiveOAuth2AuthorizedClientManager.class);
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.registrationId(clientRegistrationId).build();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, principalName,
				TestOAuth2AccessTokens.noScopes());
		given(authorizedClientManager.authorize(any())).willReturn(Mono.just(authorizedClient));
		OAuth2AuthorizedClientManagerRegisteredConfig.CLIENT_REGISTRATION_REPOSITORY = clientRegistrationRepository;
		OAuth2AuthorizedClientManagerRegisteredConfig.AUTHORIZED_CLIENT_REPOSITORY = authorizedClientRepository;
		OAuth2AuthorizedClientManagerRegisteredConfig.AUTHORIZED_CLIENT_MANAGER = authorizedClientManager;
		this.spring.register(OAuth2AuthorizedClientManagerRegisteredConfig.class).autowire();
		// @formatter:off
		this.client
				.get()
				.uri("http://localhost/authorized-client")
				.headers((headers) -> headers.setBasicAuth("user", "password")).exchange().expectStatus().isOk()
				.expectBody(String.class).isEqualTo("resolved");
		// @formatter:on
		verify(authorizedClientManager).authorize(any());
		verifyNoInteractions(clientRegistrationRepository);
		verifyNoInteractions(authorizedClientRepository);
	}

	@Test
	public void requestWhenAuthorizedClientManagerNotConfigureThenUseDefaultAuthorizedClientManager() {
		String clientRegistrationId = "client";
		String principalName = "user";
		ReactiveClientRegistrationRepository clientRegistrationRepository = mock(
				ReactiveClientRegistrationRepository.class);
		ServerOAuth2AuthorizedClientRepository authorizedClientRepository = mock(
				ServerOAuth2AuthorizedClientRepository.class);
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.registrationId(clientRegistrationId).build();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, principalName,
				TestOAuth2AccessTokens.noScopes());
		OAuth2AuthorizedClientManagerRegisteredConfig.CLIENT_REGISTRATION_REPOSITORY = clientRegistrationRepository;
		OAuth2AuthorizedClientManagerRegisteredConfig.AUTHORIZED_CLIENT_REPOSITORY = authorizedClientRepository;
		OAuth2AuthorizedClientManagerRegisteredConfig.AUTHORIZED_CLIENT_MANAGER = null;
		given(authorizedClientRepository.loadAuthorizedClient(any(), any(), any()))
				.willReturn(Mono.just(authorizedClient));
		this.spring.register(OAuth2AuthorizedClientManagerRegisteredConfig.class).autowire();
		// @formatter:off
		this.client
				.get()
				.uri("http://localhost/authorized-client")
				.headers((headers) -> headers.setBasicAuth("user", "password")).exchange().expectStatus().isOk()
				.expectBody(String.class).isEqualTo("resolved");
		// @formatter:on
	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class OAuth2AuthorizedClientManagerRegisteredConfig {

		static ReactiveClientRegistrationRepository CLIENT_REGISTRATION_REPOSITORY;
		static ServerOAuth2AuthorizedClientRepository AUTHORIZED_CLIENT_REPOSITORY;
		static ReactiveOAuth2AuthorizedClientManager AUTHORIZED_CLIENT_MANAGER;

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			return http.build();
		}

		@Bean
		ReactiveClientRegistrationRepository clientRegistrationRepository() {
			return CLIENT_REGISTRATION_REPOSITORY;
		}

		@Bean
		ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
			return AUTHORIZED_CLIENT_REPOSITORY;
		}

		@Bean
		ReactiveOAuth2AuthorizedClientManager authorizedClientManager() {
			return AUTHORIZED_CLIENT_MANAGER;
		}

		@RestController
		class Controller {

			@GetMapping("/authorized-client")
			String authorizedClient(
					@RegisteredOAuth2AuthorizedClient("client1") OAuth2AuthorizedClient authorizedClient) {
				return (authorizedClient != null) ? "resolved" : "not-resolved";
			}

		}

	}

}
