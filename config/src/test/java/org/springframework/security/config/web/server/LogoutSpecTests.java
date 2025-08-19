/*
 * Copyright 2004-present the original author or authors.
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

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.WebDriver;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.ServerHttpSecurityConfigurationBuilder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.htmlunit.server.WebTestClientHtmlUnitDriverBuilder;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

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

	@Test
	public void multipleLogoutHandlers() {
		InMemorySecurityContextRepository repository = new InMemorySecurityContextRepository();
		MultiValueMap<String, String> logoutData = new LinkedMultiValueMap<>();
		ServerLogoutHandler handler1 = (exchange, authentication) -> {
			logoutData.add("handler-header", "value1");
			return Mono.empty();
		};
		ServerLogoutHandler handler2 = (exchange, authentication) -> {
			logoutData.add("handler-header", "value2");
			return Mono.empty();
		};
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
				.securityContextRepository(repository)
				.authorizeExchange((authorize) -> authorize
						.anyExchange().authenticated())
				.formLogin(withDefaults())
				.logout((logoutSpec) -> logoutSpec.logoutHandler((handlers) -> {
					handlers.add(handler1);
					handlers.add(0, handler2);
				}))
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
		SecurityContext savedContext = repository.getSavedContext();
		assertThat(savedContext).isNotNull();
		assertThat(savedContext.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);

		loginPage = FormLoginTests.DefaultLogoutPage.to(driver).assertAt().logout();
		loginPage.assertAt().assertLogout();
		assertThat(logoutData).hasSize(1);
		assertThat(logoutData.get("handler-header")).containsExactly("value2", "value1");
		savedContext = repository.getSavedContext();
		assertThat(savedContext).isNull();
	}

	private static class InMemorySecurityContextRepository implements ServerSecurityContextRepository {

		@Nullable private SecurityContext savedContext;

		@Override
		public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
			this.savedContext = context;
			return Mono.empty();
		}

		@Override
		public Mono<SecurityContext> load(ServerWebExchange exchange) {
			return Mono.justOrEmpty(this.savedContext);
		}

		@Nullable private SecurityContext getSavedContext() {
			return this.savedContext;
		}

	}

	@RestController
	public static class HomeController {

		@GetMapping("/")
		public String ok() {
			return "ok";
		}

	}

}
