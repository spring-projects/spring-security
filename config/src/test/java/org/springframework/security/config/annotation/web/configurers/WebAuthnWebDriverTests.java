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

package org.springframework.security.config.annotation.web.configurers;

import java.time.Duration;
import java.util.EnumSet;
import java.util.Map;

import jakarta.servlet.DispatcherType;
import org.awaitility.Awaitility;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.chromium.HasCdp;
import org.openqa.selenium.devtools.HasDevTools;
import org.openqa.selenium.remote.Augmenter;
import org.openqa.selenium.remote.RemoteWebDriver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Webdriver-based tests for the WebAuthnConfigurer. This uses a full browser because
 * these features require Javascript and browser APIs to be available.
 * <p>
 * The tests are ordered to ensure that no credential is registered with Spring Security
 * before the last "end-to-end" test. It does not impact the tests for now, but should
 * avoid test pollution in the future.
 *
 * @author Daniel Garnier-Moiroux
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@ExtendWith(SpringExtension.class)
class WebAuthnWebDriverTests {

	private static String baseUrl;

	private static ChromeDriverService driverService;

	private RemoteWebDriver driver;

	private static final String USERNAME = "user";

	private static final String PASSWORD = "password";

	@BeforeAll
	static void startChromeDriverService() throws Exception {
		driverService = new ChromeDriverService.Builder().usingAnyFreePort().build();
		driverService.start();
	}

	@AfterAll
	static void stopChromeDriverService() {
		driverService.stop();
	}

	@BeforeAll
	static void setupBaseUrl(@Autowired Server server) throws Exception {
		baseUrl = "http://localhost:" + ((ServerConnector) server.getConnectors()[0]).getLocalPort();
	}

	@AfterAll
	static void stopServer(@Autowired Server server) throws Exception {
		// Close the server early and don't wait for the full context to be closed, as it
		// may take some time to get evicted from the ContextCache.
		server.stop();
	}

	@BeforeEach
	void setupDriver() {
		ChromeOptions options = new ChromeOptions();
		options.addArguments("--headless=new");
		var baseDriver = new RemoteWebDriver(driverService.getUrl(), options);
		// Enable dev tools
		this.driver = (RemoteWebDriver) new Augmenter().augment(baseDriver);
		this.driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(1));
	}

	@AfterEach
	void cleanupDriver() {
		this.driver.quit();
	}

	@Test
	@Order(1)
	void loginWhenNoValidAuthenticatorCredentialsThenRejects() {
		createVirtualAuthenticator(true);
		this.driver.get(baseUrl);
		this.driver.findElement(new By.ById("passkey-signin")).click();
		Awaitility.await()
			.atMost(Duration.ofSeconds(1))
			.untilAsserted(() -> assertThat(this.driver.getCurrentUrl()).endsWith("/login?error"));
	}

	@Test
	@Order(2)
	void registerWhenNoLabelThenRejects() {
		login();

		this.driver.get(baseUrl + "/webauthn/register");

		this.driver.findElement(new By.ById("register")).click();
		WebElement errorPopup = this.driver.findElement(new By.ById("error"));

		assertThat(errorPopup.isDisplayed()).isTrue();
		assertThat(errorPopup.getText()).isEqualTo("Error: Passkey Label is required");
	}

	@Test
	@Order(3)
	void registerWhenAuthenticatorNoUserVerificationThenRejects() {
		createVirtualAuthenticator(false);
		login();
		this.driver.get(baseUrl + "/webauthn/register");
		this.driver.findElement(new By.ById("label")).sendKeys("Virtual authenticator");
		this.driver.findElement(new By.ById("register")).click();

		Awaitility.await()
			.atMost(Duration.ofSeconds(2))
			.pollInterval(Duration.ofMillis(100))
			.untilAsserted(() -> assertHasAlert("error",
					"Registration failed. Call to navigator.credentials.create failed: The operation either timed out or was not allowed."));
	}

	/**
	 * Test in 4 steps to verify the end-to-end flow of registering an authenticator and
	 * using it to register.
	 * <ul>
	 * <li>Step 1: Log in with username / password</li>
	 * <li>Step 2: Register a credential from the virtual authenticator</li>
	 * <li>Step 3: Log out</li>
	 * <li>Step 4: Log in with the authenticator</li>
	 * </ul>
	 *
	 * This test runs last to ensure that no credential is registered when the previous
	 * tests run.
	 */
	@Test
	@Order(Integer.MAX_VALUE)
	void loginWhenAuthenticatorRegisteredThenSuccess() {
		// Setup
		createVirtualAuthenticator(true);

		// Step 1: log in with username / password
		login();

		// Step 2: register a credential from the virtual authenticator
		this.driver.get(baseUrl + "/webauthn/register");
		this.driver.findElement(new By.ById("label")).sendKeys("Virtual authenticator");
		this.driver.findElement(new By.ById("register")).click();

		//@formatter:off
		Awaitility.await()
				.atMost(Duration.ofSeconds(2))
				.untilAsserted(() -> assertHasAlert("success", "Success!"));
		//@formatter:on;

		var passkeyRows = this.driver.findElements(new By.ByCssSelector("table > tbody > tr"));
		assertThat(passkeyRows).hasSize(1)
			.first()
			.extracting((row) -> row.findElement(new By.ByCssSelector("td:first-child")))
			.extracting(WebElement::getText)
			.isEqualTo("Virtual authenticator");

		// Step 3: log out
		logout();

		// Step 4: log in with the virtual authenticator
		this.driver.get(baseUrl + "/webauthn/register");
		this.driver.findElement(new By.ById("passkey-signin")).click();
		Awaitility.await()
			.atMost(Duration.ofSeconds(1))
			.untilAsserted(() -> assertThat(this.driver.getCurrentUrl()).endsWith("/webauthn/register?continue"));
	}

	private void login() {
		this.driver.get(baseUrl);
		this.driver.findElement(new By.ById("username")).sendKeys(USERNAME);
		this.driver.findElement(new By.ById(PASSWORD)).sendKeys(PASSWORD);
		this.driver.findElement(new By.ByCssSelector("form > button[type=\"submit\"]")).click();
	}

	private void logout() {
		this.driver.get(baseUrl + "/logout");
		this.driver.findElement(new By.ByCssSelector("button")).click();
		Awaitility.await()
			.atMost(Duration.ofSeconds(1))
			.untilAsserted(() -> assertThat(this.driver.getCurrentUrl()).endsWith("/login?logout"));
	}

	private void assertHasAlert(String alertType, String alertMessage) {
		var alert = this.driver.findElement(new By.ById(alertType));
		assertThat(alert.isDisplayed())
			.withFailMessage(
					() -> alertType + " alert was not displayed. Full page source:\n\n" + this.driver.getPageSource())
			.isTrue();

		assertThat(alert.getText()).startsWith(alertMessage);
	}

	/**
	 * Add a virtual authenticator.
	 * <p>
	 * Note that Selenium docs for {@link HasCdp} strongly encourage to use
	 * {@link HasDevTools} instead. However, devtools require more dependencies and
	 * boilerplate, notably to sync the Devtools-CDP version with the current browser
	 * version, whereas CDP runs out of the box.
	 * <p>
	 * @param userIsVerified whether the authenticator simulates user verification.
	 * Setting it to false will make the ceremonies fail.
	 * @see <a href=
	 * "https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/">https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/</a>
	 */
	private void createVirtualAuthenticator(boolean userIsVerified) {
		var cdpDriver = (HasCdp) this.driver;
		cdpDriver.executeCdpCommand("WebAuthn.enable", Map.of("enableUI", false));
		// this.driver.addVirtualAuthenticator(createVirtualAuthenticatorOptions());
		//@formatter:off
		var commandResult = cdpDriver.executeCdpCommand("WebAuthn.addVirtualAuthenticator",
				Map.of(
						"options",
						Map.of(
								"protocol", "ctap2",
								"transport", "usb",
								"hasUserVerification", true,
								"hasResidentKey", true,
								"isUserVerified", userIsVerified,
								"automaticPresenceSimulation", true
						)
				));
		//@formatter:on
	}

	/**
	 * The configuration for WebAuthN tests. This configuration embeds a {@link Server},
	 * because the WebAuthN configurer needs to know the port on which the server is
	 * running to configure {@link WebAuthnConfigurer#allowedOrigins(String...)}. This
	 * requires starting the server before configuring the Security Filter chain.
	 */
	@Configuration
	@EnableWebSecurity
	static class WebAuthnConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
					User.withDefaultPasswordEncoder().username(USERNAME).password(PASSWORD).build());
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http, Server server) throws Exception {
			return http.authorizeHttpRequests((auth) -> auth.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults())
				.webAuthn((passkeys) -> passkeys.rpId("localhost")
					.rpName("Spring Security WebAuthN tests")
					.allowedOrigins("http://localhost:" + getServerPort(server)))
				.build();
		}

		@Bean
		Server server() throws Exception {
			ServletContextHandler servlet = new ServletContextHandler(ServletContextHandler.SESSIONS);
			Server server = new Server(0);
			server.setHandler(servlet);
			server.start();
			return server;
		}

		/**
		 * Ensure the server is stopped whenever the application context closes.
		 * @param server -
		 * @return -
		 */
		@Bean
		ApplicationListener<ContextClosedEvent> onContextStopped(Server server) {
			return (event) -> {
				try {
					server.stop();
				}
				catch (Exception ignored) {
				}
			};
		}

		@Autowired
		void addSecurityFilterChainToServlet(Server server, SecurityFilterChain filterChain) {
			FilterChainProxy filterChainProxy = new FilterChainProxy(filterChain);
			((ServletContextHandler) server.getHandler()).addFilter(new FilterHolder(filterChainProxy), "/*",
					EnumSet.allOf(DispatcherType.class));
		}

		private static int getServerPort(Server server) {
			return ((ServerConnector) server.getConnectors()[0]).getLocalPort();
		}

	}

}
