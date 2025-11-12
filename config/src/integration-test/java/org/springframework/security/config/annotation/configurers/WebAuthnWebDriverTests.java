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

package org.springframework.security.config.annotation.configurers;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.assertj.core.api.AbstractAssert;
import org.assertj.core.api.AbstractStringAssert;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.chromium.HasCdp;
import org.openqa.selenium.devtools.HasDevTools;
import org.openqa.selenium.remote.Augmenter;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.support.ui.FluentWait;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockPropertySource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Webdriver-based tests for the WebAuthnConfigurer. This uses a full browser because
 * these features require Javascript and browser APIs to be available.
 *
 * @author Daniel Garnier-Moiroux
 */
@Disabled
class WebAuthnWebDriverTests {

	private String baseUrl;

	private static ChromeDriverService driverService;

	private Server server;

	private RemoteWebDriver driver;

	private static final String USERNAME = "user";

	private static final String PASSWORD = "password";

	private String authenticatorId = null;

	@BeforeAll
	static void startChromeDriverService() throws Exception {
		driverService = new ChromeDriverService.Builder().usingAnyFreePort().build();
		driverService.start();
	}

	@AfterAll
	static void stopChromeDriverService() {
		driverService.stop();
	}

	@BeforeEach
	void startServer() throws Exception {
		// Create the server on port 8080
		this.server = new Server(0);

		// Set up the ServletContextHandler
		ServletContextHandler contextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
		contextHandler.setContextPath("/");
		this.server.setHandler(contextHandler);
		this.server.start();
		int serverPort = ((ServerConnector) this.server.getConnectors()[0]).getLocalPort();
		this.baseUrl = "http://localhost:" + serverPort;

		// Set up Spring application context
		AnnotationConfigWebApplicationContext applicationContext = new AnnotationConfigWebApplicationContext();
		applicationContext.register(WebAuthnConfiguration.class);
		applicationContext.setServletContext(contextHandler.getServletContext());

		// Add the server port
		MockPropertySource propertySource = new MockPropertySource().withProperty("server.port", serverPort);
		applicationContext.getEnvironment().getPropertySources().addFirst(propertySource);

		// Register the filter chain
		DelegatingFilterProxy filterProxy = new DelegatingFilterProxy("securityFilterChain", applicationContext);
		FilterHolder filterHolder = new FilterHolder(filterProxy);
		contextHandler.addFilter(filterHolder, "/*", null);
	}

	@AfterEach
	void stopServer() throws Exception {
		this.server.stop();
	}

	@BeforeEach
	void setupDriver() {
		ChromeOptions options = new ChromeOptions();
		options.addArguments("--headless=new");
		RemoteWebDriver baseDriver = new RemoteWebDriver(driverService.getUrl(), options);
		// Enable dev tools
		this.driver = (RemoteWebDriver) new Augmenter().augment(baseDriver);
		this.driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(1));
	}

	@AfterEach
	void cleanupDriver() {
		this.driver.quit();
	}

	@Test
	void loginWhenNoValidAuthenticatorCredentialsThenRejects() {
		createVirtualAuthenticator(true);
		this.getAndWait("/", "/login");
		this.driver.findElement(signinWithPasskeyButton()).click();
		await(() -> assertThat(this.driver.getCurrentUrl()).endsWith("/login?error"));
	}

	@Test
	void registerWhenNoLabelThenRejects() {
		login();

		this.getAndWait("/webauthn/register");

		this.driver.findElement(registerPasskeyButton()).click();
		assertHasAlertStartingWith("error", "Error: Passkey Label is required");
	}

	@Test
	void registerWhenAuthenticatorNoUserVerificationThenRejects() {
		createVirtualAuthenticator(false);
		login();
		this.getAndWait("/webauthn/register");
		this.driver.findElement(passkeyLabel()).sendKeys("Virtual authenticator");
		this.driver.findElement(registerPasskeyButton()).click();

		await(() -> assertHasAlertStartingWith("error",
				"Registration failed. Call to navigator.credentials.create failed:"));
	}

	/**
	 * Test in 4 steps to verify the end-to-end flow of registering an authenticator and
	 * using it to register.
	 * <ul>
	 * <li>Step 1: Log in with username / password</li>
	 * <li>Step 2: Register a credential from the virtual authenticator</li>
	 * <li>Step 3: Log out</li>
	 * <li>Step 4: Log in with the authenticator (no allowCredentials)</li>
	 * <li>Step 5: Log in again with the same authenticator (with allowCredentials)</li>
	 * </ul>
	 */
	@Test
	void loginWhenAuthenticatorRegisteredThenSuccess() {
		// Setup
		createVirtualAuthenticator(true);

		// Step 1: log in with username / password
		login();

		// Step 2: register a credential from the virtual authenticator
		this.getAndWait("/webauthn/register");
		this.driver.findElement(passkeyLabel()).sendKeys("Virtual authenticator");
		this.driver.findElement(registerPasskeyButton()).click();

		// Ensure the page location has changed before performing further assertions.
		// This is required because the location change is asynchronously performed in
		// javascript, and performing assertions based on this.driver.findElement(...)
		// may result in a StaleElementReferenceException.
		await(() -> assertThat(this.driver.getCurrentUrl()).endsWith("/webauthn/register?success"));
		await(() -> assertHasAlertStartingWith("success", "Success!"));

		List<WebElement> passkeyRows = this.driver.findElements(passkeyTableRows());
		assertThat(passkeyRows).hasSize(1)
			.first()
			.extracting((row) -> row.findElement(firstCell()))
			.extracting(WebElement::getText)
			.isEqualTo("Virtual authenticator");

		// Step 3: log out
		logout();

		// Step 4: log in with the virtual authenticator
		this.getAndWait("/webauthn/register", "/login");
		this.driver.findElement(signinWithPasskeyButton()).click();
		await(() -> assertThat(this.driver.getCurrentUrl()).endsWith("/webauthn/register?continue"));

		// Step 5: authenticate while being already logged in
		// This simulates some use-cases with MFA. Since the user is already logged in,
		// the "allowCredentials" property is populated
		this.getAndWait("/login");
		this.driver.findElement(signinWithPasskeyButton()).click();
		await(() -> assertThat(this.driver.getCurrentUrl()).endsWith("/"));
	}

	@Test
	void registerWhenAuthenticatorAlreadyRegisteredThenRejects() {
		createVirtualAuthenticator(true);
		login();
		registerAuthenticator("Virtual authenticator");

		// Cannot re-register the same authenticator because excludeCredentials
		// is not empty and contains the given authenticator
		this.driver.findElement(passkeyLabel()).sendKeys("Same authenticator");
		this.driver.findElement(registerPasskeyButton()).click();

		await(() -> assertHasAlertStartingWith("error", "Registration failed"));
	}

	@Test
	void registerSecondAuthenticatorThenSucceeds() {
		createVirtualAuthenticator(true);
		login();

		registerAuthenticator("Virtual authenticator");
		this.getAndWait("/webauthn/register");
		List<WebElement> passkeyRows = this.driver.findElements(passkeyTableRows());
		assertThat(passkeyRows).hasSize(1)
			.first()
			.extracting((row) -> row.findElement(firstCell()))
			.extracting(WebElement::getText)
			.isEqualTo("Virtual authenticator");

		// Create second authenticator and register
		removeAuthenticator();
		createVirtualAuthenticator(true);
		registerAuthenticator("Second virtual authenticator");

		this.getAndWait("/webauthn/register");

		passkeyRows = this.driver.findElements(passkeyTableRows());
		assertThat(passkeyRows).hasSize(2)
			.extracting((row) -> row.findElement(firstCell()))
			.extracting(WebElement::getText)
			.contains("Second virtual authenticator");
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
		if (StringUtils.hasText(this.authenticatorId)) {
			throw new IllegalStateException("Authenticator already exists, please remove it before re-creating one");
		}
		HasCdp cdpDriver = (HasCdp) this.driver;
		cdpDriver.executeCdpCommand("WebAuthn.enable", Map.of("enableUI", false));
		// this.driver.addVirtualAuthenticator(createVirtualAuthenticatorOptions());
		//@formatter:off
		Map<String, Object> cmdResponse = cdpDriver.executeCdpCommand("WebAuthn.addVirtualAuthenticator",
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
		this.authenticatorId = cmdResponse.get("authenticatorId").toString();
	}

	private void removeAuthenticator() {
		HasCdp cdpDriver = (HasCdp) this.driver;
		cdpDriver.executeCdpCommand("WebAuthn.removeVirtualAuthenticator",
				Map.of("authenticatorId", this.authenticatorId));
		this.authenticatorId = null;
	}

	private void login() {
		this.getAndWait("/", "/login");
		this.driver.findElement(usernameField()).sendKeys(USERNAME);
		this.driver.findElement(passwordField()).sendKeys(PASSWORD);
		this.driver.findElement(signinWithUsernamePasswordButton()).click();
		// Ensure login has completed
		await(() -> assertThat(this.driver.getCurrentUrl()).doesNotContain("/login"));
	}

	private void logout() {
		this.getAndWait("/logout");
		this.driver.findElement(logoutButton()).click();
		await(() -> assertThat(this.driver.getCurrentUrl()).endsWith("/login?logout"));
	}

	private void registerAuthenticator(String passkeyName) {
		this.getAndWait("/webauthn/register");
		this.driver.findElement(passkeyLabel()).sendKeys(passkeyName);
		this.driver.findElement(registerPasskeyButton()).click();
		await(() -> assertThat(this.driver.getCurrentUrl()).endsWith("/webauthn/register?success"));
	}

	private AbstractStringAssert<?> assertHasAlertStartingWith(String alertType, String alertMessage) {
		WebElement alert = this.driver.findElement(new By.ById(alertType));
		assertThat(alert.isDisplayed())
			.withFailMessage(
					() -> alertType + " alert was not displayed. Full page source:\n\n" + this.driver.getPageSource())
			.isTrue();

		return assertThat(alert.getText()).startsWith(alertMessage);
	}

	/**
	 * Await until the assertion passes. If the assertion fails, it will display the
	 * assertion error in stdout. WebDriver-related exceptions are ignored, so that
	 * {@code assertion}s can interact with the page and be retried on error, e.g.
	 * {@code assertThat(this.driver.findElement(By.Id("some-id")).isNotNull()}.
	 */
	private void await(Supplier<AbstractAssert<?, ?>> assertion) {
		new FluentWait<>(this.driver).withTimeout(Duration.ofSeconds(2))
			.pollingEvery(Duration.ofMillis(100))
			.ignoring(AssertionError.class, WebDriverException.class)
			.until((d) -> {
				assertion.get();
				return true;
			});
	}

	private void getAndWait(String endpoint) {
		this.getAndWait(endpoint, endpoint);
	}

	private void getAndWait(String endpoint, String redirectUrl) {
		this.driver.get(this.baseUrl + endpoint);
		this.await(() -> assertThat(this.driver.getCurrentUrl()).endsWith(redirectUrl));
	}

	private static By.ById passkeyLabel() {
		return new By.ById("label");
	}

	private static By.ById registerPasskeyButton() {
		return new By.ById("register");
	}

	private static By.ByCssSelector passkeyTableRows() {
		return new By.ByCssSelector("table > tbody > tr");
	}

	private static By.ByCssSelector firstCell() {
		return new By.ByCssSelector("td:first-child");
	}

	private static By.ById passwordField() {
		return new By.ById(PASSWORD);
	}

	private static By.ById usernameField() {
		return new By.ById("username");
	}

	private static By.ByCssSelector signinWithUsernamePasswordButton() {
		return new By.ByCssSelector("form > button[type=\"submit\"]");
	}

	private static By.ById signinWithPasskeyButton() {
		return new By.ById("passkey-signin");
	}

	private static By.ByCssSelector logoutButton() {
		return new By.ByCssSelector("button");
	}

	private static By.ByCssSelector deletePasskeyButton() {
		return new By.ByCssSelector("table > tbody > tr > button");
	}

	/**
	 * The configuration for WebAuthN tests. It accesses the Server's current port, so we
	 * can configurer WebAuthnConfigurer#allowedOrigin
	 */
	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class WebAuthnConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
					User.withDefaultPasswordEncoder().username(USERNAME).password(PASSWORD).build());
		}

		@Bean
		FilterChainProxy securityFilterChain(HttpSecurity http, Environment environment) throws Exception {
			SecurityFilterChain securityFilterChain = http
				.authorizeHttpRequests((auth) -> auth.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults())
				.webAuthn((passkeys) -> passkeys.rpId("localhost")
					.rpName("Spring Security WebAuthN tests")
					.allowedOrigins("http://localhost:" + environment.getProperty("server.port")))
				.build();
			return new FilterChainProxy(securityFilterChain);
		}

	}

}
