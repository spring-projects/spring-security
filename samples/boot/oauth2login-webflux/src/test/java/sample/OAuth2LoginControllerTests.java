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

package sample;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import sample.web.OAuth2LoginController;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.result.method.annotation.OAuth2AuthorizedClientArgumentResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.reactive.result.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.result.view.ViewResolver;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOidcLogin;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * @author Josh Cummings
 */
@RunWith(SpringRunner.class)
@WebFluxTest(OAuth2LoginController.class)
public class OAuth2LoginControllerTests {

		@Autowired
		OAuth2LoginController controller;

		@Autowired
		ViewResolver viewResolver;

		@Mock
		ReactiveClientRegistrationRepository clientRegistrationRepository;

		WebTestClient rest;

		@Before
		public void setup() {
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository =
					new WebSessionServerOAuth2AuthorizedClientRepository();

			this.rest = WebTestClient
					.bindToController(this.controller)
					.apply(springSecurity())
					.webFilter(new SecurityContextServerWebExchangeWebFilter())
					.argumentResolvers(c -> {
						c.addCustomResolver(new AuthenticationPrincipalArgumentResolver(new ReactiveAdapterRegistry()));
						c.addCustomResolver(new OAuth2AuthorizedClientArgumentResolver
								(this.clientRegistrationRepository, authorizedClientRepository));
					})
					.viewResolvers(c -> c.viewResolver(this.viewResolver))
					.build();
		}

		@Test
		public void indexGreetsAuthenticatedUser() {
			this.rest.mutateWith(mockOidcLogin())
					.get().uri("/").exchange()
					.expectBody(String.class).value(containsString("test-subject"));
		}
}
