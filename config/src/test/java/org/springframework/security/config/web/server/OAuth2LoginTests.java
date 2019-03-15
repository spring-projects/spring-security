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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Rule;
import org.junit.Test;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.htmlunit.server.WebTestClientHtmlUnitDriverBuilder;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationExchanges;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.TestOAuth2Users;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class OAuth2LoginTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private WebFilterChainProxy springSecurity;

	private static ClientRegistration github = CommonOAuth2Provider.GITHUB
			.getBuilder("github")
			.clientId("client")
			.clientSecret("secret")
			.build();

	@Test
	public void defaultLoginPageWithMultipleClientRegistrationsThenLinks() {
		this.spring.register(OAuth2LoginWithMulitpleClientRegistrations.class).autowire();

		WebTestClient webTestClient = WebTestClientBuilder
				.bindToWebFilters(this.springSecurity)
				.build();

		WebDriver driver = WebTestClientHtmlUnitDriverBuilder
				.webTestClientSetup(webTestClient)
				.build();

		FormLoginTests.DefaultLoginPage loginPage = FormLoginTests.HomePage
				.to(driver, FormLoginTests.DefaultLoginPage.class)
				.assertAt()
				.assertLoginFormNotPresent()
				.oauth2Login()
					.assertClientRegistrationByName(this.github.getClientName())
					.and();
	}

	@EnableWebFluxSecurity
	static class OAuth2LoginWithMulitpleClientRegistrations {
		@Bean
		InMemoryReactiveClientRegistrationRepository clientRegistrationRepository() {
			ClientRegistration google = CommonOAuth2Provider.GOOGLE
					.getBuilder("google")
					.clientId("client")
					.clientSecret("secret")
					.build();
			return new InMemoryReactiveClientRegistrationRepository(github, google);
		}
	}

	@Test
	public void defaultLoginPageWithSingleClientRegistrationThenRedirect() {
		this.spring.register(OAuth2LoginWithSingleClientRegistrations.class).autowire();

		WebTestClient webTestClient = WebTestClientBuilder
				.bindToWebFilters(new GitHubWebFilter(), this.springSecurity)
				.build();

		WebDriver driver = WebTestClientHtmlUnitDriverBuilder
				.webTestClientSetup(webTestClient)
				.build();

		driver.get("http://localhost/");

		assertThat(driver.getCurrentUrl()).startsWith("https://github.com/login/oauth/authorize");
	}

	@EnableWebFluxSecurity
	static class OAuth2LoginWithSingleClientRegistrations {
		@Bean
		InMemoryReactiveClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryReactiveClientRegistrationRepository(github);
		}
	}

	@Test
	public void oauth2LoginWhenCustomObjectsThenUsed() {
		this.spring.register(OAuth2LoginWithSingleClientRegistrations.class,
				OAuth2LoginMockAuthenticationManagerConfig.class).autowire();

		WebTestClient webTestClient = WebTestClientBuilder
				.bindToWebFilters(this.springSecurity)
				.build();

		OAuth2LoginMockAuthenticationManagerConfig config = this.spring.getContext()
				.getBean(OAuth2LoginMockAuthenticationManagerConfig.class);
		ServerAuthenticationConverter converter = config.authenticationConverter;
		ReactiveAuthenticationManager manager = config.manager;

		OAuth2AuthorizationExchange exchange = TestOAuth2AuthorizationExchanges.success();
		OAuth2User user = TestOAuth2Users.create();
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.noScopes();

		OAuth2LoginAuthenticationToken result = new OAuth2LoginAuthenticationToken(github, exchange, user, user.getAuthorities(), accessToken);

		when(converter.convert(any())).thenReturn(Mono.just(new TestingAuthenticationToken("a", "b", "c")));
		when(manager.authenticate(any())).thenReturn(Mono.just(result));

		webTestClient.get()
			.uri("/login/oauth2/code/github")
			.exchange()
			.expectStatus().is3xxRedirection();

		verify(converter).convert(any());
		verify(manager).authenticate(any());
	}

	@Configuration
	static class OAuth2LoginMockAuthenticationManagerConfig {
		ReactiveAuthenticationManager manager = mock(ReactiveAuthenticationManager.class);

		ServerAuthenticationConverter authenticationConverter = mock(ServerAuthenticationConverter.class);

		@Bean
		public SecurityWebFilterChain springSecurityFilter(ServerHttpSecurity http) {
			http
				.authorizeExchange()
					.anyExchange().authenticated()
					.and()
				.oauth2Login()
					.authenticationConverter(authenticationConverter)
					.authenticationManager(manager);
			return http.build();
		}
	}

	static class GitHubWebFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			if (exchange.getRequest().getURI().getHost().equals("github.com")) {
				return exchange.getResponse().setComplete();
			}
			return chain.filter(exchange);
		}
	}
}
