/*
 * Copyright 2002-2021 the original author or authors.
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

import org.junit.jupiter.api.Test;
import org.openqa.selenium.WebDriver;

import org.springframework.security.config.annotation.web.reactive.ServerHttpSecurityConfigurationBuilder;
import org.springframework.security.htmlunit.server.WebTestClientHtmlUnitDriverBuilder;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Shazin Sadakath
 * @since 5.0
 */
public class LogoutSpecTests {

	private ServerHttpSecurity http = ServerHttpSecurityConfigurationBuilder.httpWithDefaultAuthentication();

	@Test
	public void defaultLogout() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
			.authorizeExchange((authorize) -> authorize
				.anyExchange().authenticated())
			.formLogin(withDefaults())
			.build();
		WebTestClient webTestClient = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		WebDriver driver = WebTestClientHtmlUnitDriverBuilder
				.webTestClientSetup(webTestClient)
				.build();
		// @formatter:on
		FormLoginTests.DefaultLoginPage loginPage = FormLoginTests.HomePage
			.to(driver, FormLoginTests.DefaultLoginPage.class)
			.assertAt();
		// @formatter:off
		loginPage = loginPage.loginForm()
				.username("user")
				.password("invalid")
				.submit(FormLoginTests.DefaultLoginPage.class)
				.assertError();
		FormLoginTests.HomePage homePage = loginPage.loginForm()
				.username("user")
				.password("password")
				.submit(FormLoginTests.HomePage.class);
		// @formatter:on
		homePage.assertAt();
		loginPage = FormLoginTests.DefaultLogoutPage.to(driver).assertAt().logout();
		loginPage.assertAt().assertLogout();
	}

	@Test
	public void customLogout() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
			.authorizeExchange((authorize) -> authorize
				.anyExchange().authenticated())
			.formLogin(withDefaults())
			.logout((logout) -> logout
				.requiresLogout(ServerWebExchangeMatchers.pathMatchers("/custom-logout")))
			.build();
		WebTestClient webTestClient = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		WebDriver driver = WebTestClientHtmlUnitDriverBuilder
				.webTestClientSetup(webTestClient)
				.build();
		// @formatter:on
		FormLoginTests.DefaultLoginPage loginPage = FormLoginTests.HomePage
			.to(driver, FormLoginTests.DefaultLoginPage.class)
			.assertAt();
		// @formatter:off
		loginPage = loginPage.loginForm()
					.username("user")
					.password("invalid")
					.submit(FormLoginTests.DefaultLoginPage.class)
				.assertError();
		FormLoginTests.HomePage homePage = loginPage.loginForm()
				.username("user")
				.password("password")
				.submit(FormLoginTests.HomePage.class);
		homePage.assertAt();
		// @formatter:on
		driver.get("http://localhost/custom-logout");
		FormLoginTests.DefaultLoginPage.create(driver).assertAt().assertLogout();
	}

	@Test
	public void logoutWhenCustomLogoutInLambdaThenCustomLogoutUsed() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
				.authorizeExchange((authorize) -> authorize
						.anyExchange().authenticated()
				)
				.formLogin(withDefaults())
				.logout((logout) -> logout
						.requiresLogout(ServerWebExchangeMatchers.pathMatchers("/custom-logout"))
				)
				.build();
		WebTestClient webTestClient = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		WebDriver driver = WebTestClientHtmlUnitDriverBuilder
				.webTestClientSetup(webTestClient)
				.build();
		// @formatter:on
		FormLoginTests.DefaultLoginPage loginPage = FormLoginTests.HomePage
			.to(driver, FormLoginTests.DefaultLoginPage.class)
			.assertAt();
		// @formatter:off
		loginPage = loginPage.loginForm()
				.username("user")
				.password("invalid")
				.submit(FormLoginTests.DefaultLoginPage.class)
				.assertError();
		FormLoginTests.HomePage homePage = loginPage.loginForm()
				.username("user").password("password")
				.submit(FormLoginTests.HomePage.class);
		// @formatter:on
		homePage.assertAt();
		driver.get("http://localhost/custom-logout");
		FormLoginTests.DefaultLoginPage.create(driver).assertAt().assertLogout();
	}

	@Test
	public void logoutWhenDisabledThenDefaultLogoutPageDoesNotExist() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
			.authorizeExchange((authorize) -> authorize
				.anyExchange().authenticated())
			.formLogin(withDefaults())
			.logout((logout) -> logout.disable())
			.build();
		WebTestClient webTestClient = WebTestClientBuilder
				.bindToControllerAndWebFilters(HomeController.class, securityWebFilter)
				.build();
		WebDriver driver = WebTestClientHtmlUnitDriverBuilder
				.webTestClientSetup(webTestClient)
				.build();
		// @formatter:on
		FormLoginTests.DefaultLoginPage loginPage = FormLoginTests.HomePage
			.to(driver, FormLoginTests.DefaultLoginPage.class)
			.assertAt();
		// @formatter:off
		FormLoginTests.HomePage homePage = loginPage.loginForm()
				.username("user")
				.password("password")
				.submit(FormLoginTests.HomePage.class);
		// @formatter:on
		homePage.assertAt();
		FormLoginTests.DefaultLogoutPage.to(driver);
		assertThat(driver.getPageSource()).isEmpty();
	}

	@Test
	public void logoutWhenCustomSecurityContextRepositoryThenLogsOut() {
		WebSessionServerSecurityContextRepository repository = new WebSessionServerSecurityContextRepository();
		repository.setSpringSecurityContextAttrName("CUSTOM_CONTEXT_ATTR");
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
			.securityContextRepository(repository)
			.authorizeExchange((authorize) -> authorize
				.anyExchange().authenticated())
			.formLogin(withDefaults())
			.logout(withDefaults())
			.build();
		WebTestClient webTestClient = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		WebDriver driver = WebTestClientHtmlUnitDriverBuilder
				.webTestClientSetup(webTestClient)
				.build();
		// @formatter:on
		FormLoginTests.DefaultLoginPage loginPage = FormLoginTests.HomePage
			.to(driver, FormLoginTests.DefaultLoginPage.class)
			.assertAt();
		// @formatter:off
		FormLoginTests.HomePage homePage = loginPage.loginForm()
				.username("user")
				.password("password")
				.submit(FormLoginTests.HomePage.class);
		// @formatter:on
		homePage.assertAt();
		FormLoginTests.DefaultLogoutPage.to(driver).assertAt().logout();
		FormLoginTests.HomePage.to(driver, FormLoginTests.DefaultLoginPage.class).assertAt();
	}

	@RestController
	public static class HomeController {

		@GetMapping("/")
		public String ok() {
			return "ok";
		}

	}

}
