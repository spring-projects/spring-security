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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Rule;
import org.junit.Test;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.annotation.web.reactive.ServerHttpSecurityConfigurationBuilder;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.htmlunit.server.WebTestClientHtmlUnitDriverBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ServerWebExchange;

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

	private ClientRegistration github = CommonOAuth2Provider.GITHUB
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
			ClientRegistration github = CommonOAuth2Provider.GITHUB
					.getBuilder("github")
					.clientId("client")
					.clientSecret("secret")
					.build();
			ClientRegistration google = CommonOAuth2Provider.GOOGLE
					.getBuilder("google")
					.clientId("client")
					.clientSecret("secret")
					.build();
			return new InMemoryReactiveClientRegistrationRepository(github, google);
		}
	}
}
