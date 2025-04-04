/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.server.csrf;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Eric Deandrea
 * @author Thomas Vitale
 * @author Alonso Araya
 * @author Alex Montoya
 * @since 5.1
 */
class CookieServerCsrfTokenRepositoryTests {

	private CookieServerCsrfTokenRepository csrfTokenRepository;

	private MockServerHttpRequest.BaseBuilder<?> request;

	private String expectedHeaderName = CookieServerCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME;

	private String expectedParameterName = CookieServerCsrfTokenRepository.DEFAULT_CSRF_PARAMETER_NAME;

	private Duration expectedMaxAge = Duration.ofSeconds(-1);

	private String expectedDomain = null;

	private String expectedPath = "/";

	private boolean expectedSecure = false;

	private boolean expectedHttpOnly = true;

	private String expectedCookieName = CookieServerCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;

	private String expectedCookieValue = "csrfToken";

	private String expectedSameSitePolicy = null;

	@BeforeEach
	void setUp() {
		this.csrfTokenRepository = new CookieServerCsrfTokenRepository();
		this.request = MockServerHttpRequest.get("/someUri");
	}

	@Test
	void generateTokenWhenDefaultThenDefaults() {
		generateTokenAndAssertExpectedValues();
	}

	@Test
	void generateTokenWhenCustomHeaderThenCustomHeader() {
		setExpectedHeaderName("someHeader");
		generateTokenAndAssertExpectedValues();
	}

	@Test
	void generateTokenWhenCustomParameterThenCustomParameter() {
		setExpectedParameterName("someParam");
		generateTokenAndAssertExpectedValues();
	}

	@Test
	void generateTokenWhenCustomHeaderAndParameterThenCustomHeaderAndParameter() {
		setExpectedHeaderName("someHeader");
		setExpectedParameterName("someParam");
		generateTokenAndAssertExpectedValues();
	}

	@Test
	void saveTokenWhenNoSubscriptionThenNotWritten() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		this.csrfTokenRepository.saveToken(exchange, createToken());
		assertThat(exchange.getResponse().getCookies().getFirst(this.expectedCookieName)).isNull();
	}

	@Test
	void saveTokenWhenDefaultThenDefaults() {
		saveAndAssertExpectedValues(createToken());
	}

	@Test
	void saveTokenWhenNullThenDeletes() {
		saveAndAssertExpectedValues(null);
	}

	@Test
	void saveTokenWhenHttpOnlyFalseThenHttpOnlyFalse() {
		setExpectedHttpOnly(false);
		saveAndAssertExpectedValues(createToken());
	}

	@Test
	void saveTokenWhenCookieMaxAgeThenCookieMaxAge() {
		setExpectedCookieMaxAge(3600);
		saveAndAssertExpectedValues(createToken());
	}

	@Test
	void saveTokenWhenSameSiteThenCookieSameSite() {
		setExpectedSameSitePolicy("Lax");
		saveAndAssertExpectedValues(createToken());
	}

	@Test
	void saveTokenWhenCustomPropertiesThenCustomProperties() {
		setExpectedDomain("spring.io");
		setExpectedCookieName("csrfCookie");
		setExpectedPath("/some/path");
		setExpectedHeaderName("headerName");
		setExpectedParameterName("paramName");
		setExpectedSameSitePolicy("Strict");
		setExpectedCookieMaxAge(3600);
		saveAndAssertExpectedValues(createToken());
	}

	@Test
	void saveTokenWhenCustomPropertiesThenCustomPropertiesUsingCustomizer() {
		String expectedDomain = "spring.io";
		int expectedMaxAge = 3600;
		String expectedPath = "/some/path";
		String expectedSameSite = "Strict";

		setExpectedCookieName("csrfCookie");

		setExpectedHeaderName("headerName");
		setExpectedParameterName("paramName");

		CsrfToken token = createToken();

		this.csrfTokenRepository.setCookieCustomizer((customizer) -> {
			customizer.domain(expectedDomain);
			customizer.maxAge(expectedMaxAge);
			customizer.path(expectedPath);
			customizer.sameSite(expectedSameSite);
		});

		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		this.csrfTokenRepository.saveToken(exchange, token).block();
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst(this.expectedCookieName);
		assertThat(cookie).isNotNull();
		assertThat(cookie.getMaxAge()).isEqualTo(Duration.of(expectedMaxAge, ChronoUnit.SECONDS));
		assertThat(cookie.getDomain()).isEqualTo(expectedDomain);
		assertThat(cookie.getPath()).isEqualTo(expectedPath);
		assertThat(cookie.getSameSite()).isEqualTo(expectedSameSite);
		assertThat(cookie.isSecure()).isEqualTo(this.expectedSecure);
		assertThat(cookie.isHttpOnly()).isEqualTo(this.expectedHttpOnly);
		assertThat(cookie.getName()).isEqualTo(this.expectedCookieName);
		assertThat(cookie.getValue()).isEqualTo(this.expectedCookieValue);
	}

	@Test
	void saveTokenWhenSslInfoPresentThenSecure() {
		this.request.sslInfo(new MockSslInfo());
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		this.csrfTokenRepository.saveToken(exchange, createToken()).block();
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst(this.expectedCookieName);
		assertThat(cookie).isNotNull();
		assertThat(cookie.isSecure()).isTrue();
	}

	@Test
	void saveTokenWhenSslInfoNullThenNotSecure() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		this.csrfTokenRepository.saveToken(exchange, createToken()).block();
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst(this.expectedCookieName);
		assertThat(cookie).isNotNull();
		assertThat(cookie.isSecure()).isFalse();
	}

	@Test
	void saveTokenWhenSecureFlagTrueThenSecure() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		this.csrfTokenRepository.setSecure(true);
		this.csrfTokenRepository.saveToken(exchange, createToken()).block();
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst(this.expectedCookieName);
		assertThat(cookie).isNotNull();
		assertThat(cookie.isSecure()).isTrue();
	}

	@Test
	void saveTokenWhenSecureFlagTrueThenSecureUsingCustomizer() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		this.csrfTokenRepository.setCookieCustomizer((customizer) -> customizer.secure(true));
		this.csrfTokenRepository.saveToken(exchange, createToken()).block();
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst(this.expectedCookieName);
		assertThat(cookie).isNotNull();
		assertThat(cookie.isSecure()).isTrue();
	}

	@Test
	void saveTokenWhenSecureFlagFalseThenNotSecure() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		this.csrfTokenRepository.setSecure(false);
		this.csrfTokenRepository.saveToken(exchange, createToken()).block();
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst(this.expectedCookieName);
		assertThat(cookie).isNotNull();
		assertThat(cookie.isSecure()).isFalse();
	}

	@Test
	void saveTokenWhenSecureFlagFalseThenNotSecureUsingCustomizer() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		this.csrfTokenRepository.setCookieCustomizer((customizer) -> customizer.secure(false));
		this.csrfTokenRepository.saveToken(exchange, createToken()).block();
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst(this.expectedCookieName);
		assertThat(cookie).isNotNull();
		assertThat(cookie.isSecure()).isFalse();
	}

	@Test
	void saveTokenWhenSecureFlagFalseAndSslInfoThenNotSecure() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		this.request.sslInfo(new MockSslInfo());
		this.csrfTokenRepository.setSecure(false);
		this.csrfTokenRepository.saveToken(exchange, createToken()).block();
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst(this.expectedCookieName);
		assertThat(cookie).isNotNull();
		assertThat(cookie.isSecure()).isFalse();
	}

	@Test
	void saveTokenWhenSecureFlagFalseAndSslInfoThenNotSecureUsingCustomizer() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		this.request.sslInfo(new MockSslInfo());
		this.csrfTokenRepository.setCookieCustomizer((customizer) -> customizer.secure(false));
		this.csrfTokenRepository.saveToken(exchange, createToken()).block();
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst(this.expectedCookieName);
		assertThat(cookie).isNotNull();
		assertThat(cookie.isSecure()).isFalse();
	}

	@Test
	void loadTokenWhenCookieExistThenTokenFound() {
		loadAndAssertExpectedValues();
	}

	@Test
	void loadTokenWhenCustomThenTokenFound() {
		setExpectedParameterName("paramName");
		setExpectedHeaderName("headerName");
		setExpectedCookieName("csrfCookie");
		saveAndAssertExpectedValues(createToken());
	}

	@Test
	void loadTokenWhenNoCookiesThenNullToken() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		CsrfToken csrfToken = this.csrfTokenRepository.loadToken(exchange).block();
		assertThat(csrfToken).isNull();
	}

	@Test
	void loadTokenWhenCookieExistsWithNoValue() {
		setExpectedCookieValue("");
		loadAndAssertExpectedValues();
	}

	@Test
	void loadTokenWhenCookieExistsWithNullValue() {
		setExpectedCookieValue(null);
		loadAndAssertExpectedValues();
	}

	// gh-16820
	@Test
	void withHttpOnlyFalseWhenCookieCustomizerThenStillDefaultsToFalse() {
		CookieServerCsrfTokenRepository repository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
		repository.setCookieCustomizer((customizer) -> customizer.maxAge(1000));
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/dummy");
		MockServerWebExchange exchange = MockServerWebExchange.from(request);
		CsrfToken csrfToken = repository.generateToken(exchange).block();
		repository.saveToken(exchange, csrfToken).block();
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst("XSRF-TOKEN");
		assertThat(cookie).isNotNull();
		assertThat(cookie.getMaxAge().getSeconds()).isEqualTo(1000);
		assertThat(cookie.isHttpOnly()).isEqualTo(Boolean.FALSE);
	}

	private void setExpectedHeaderName(String expectedHeaderName) {
		this.csrfTokenRepository.setHeaderName(expectedHeaderName);
		this.expectedHeaderName = expectedHeaderName;
	}

	private void setExpectedParameterName(String expectedParameterName) {
		this.csrfTokenRepository.setParameterName(expectedParameterName);
		this.expectedParameterName = expectedParameterName;
	}

	private void setExpectedDomain(String expectedDomain) {
		this.csrfTokenRepository.setCookieDomain(expectedDomain);
		this.expectedDomain = expectedDomain;
	}

	private void setExpectedPath(String expectedPath) {
		this.csrfTokenRepository.setCookiePath(expectedPath);
		this.expectedPath = expectedPath;
	}

	private void setExpectedHttpOnly(boolean expectedHttpOnly) {
		this.expectedHttpOnly = expectedHttpOnly;
		this.csrfTokenRepository.setCookieHttpOnly(expectedHttpOnly);
	}

	private void setExpectedCookieName(String expectedCookieName) {
		this.expectedCookieName = expectedCookieName;
		this.csrfTokenRepository.setCookieName(expectedCookieName);
	}

	private void setExpectedCookieMaxAge(int expectedCookieMaxAge) {
		this.csrfTokenRepository.setCookieMaxAge(expectedCookieMaxAge);
		this.expectedMaxAge = Duration.ofSeconds(expectedCookieMaxAge);
	}

	private void setExpectedSameSitePolicy(String sameSitePolicy) {
		this.csrfTokenRepository.setCookieCustomizer((customizer) -> customizer.sameSite(sameSitePolicy));
		this.expectedSameSitePolicy = sameSitePolicy;
	}

	private void setExpectedCookieValue(String expectedCookieValue) {
		this.expectedCookieValue = expectedCookieValue;
	}

	private void loadAndAssertExpectedValues() {
		MockServerHttpRequest.BodyBuilder request = MockServerHttpRequest.post("/someUri")
			.cookie(new HttpCookie(this.expectedCookieName, this.expectedCookieValue));
		MockServerWebExchange exchange = MockServerWebExchange.from(request);
		CsrfToken csrfToken = this.csrfTokenRepository.loadToken(exchange).block();
		if (StringUtils.hasText(this.expectedCookieValue)) {
			assertThat(csrfToken).isNotNull();
			assertThat(csrfToken.getHeaderName()).isEqualTo(this.expectedHeaderName);
			assertThat(csrfToken.getParameterName()).isEqualTo(this.expectedParameterName);
			assertThat(csrfToken.getToken()).isEqualTo(this.expectedCookieValue);
		}
		else {
			assertThat(csrfToken).isNull();
		}
	}

	private void saveAndAssertExpectedValues(CsrfToken token) {
		if (token == null) {
			this.expectedMaxAge = Duration.ofSeconds(0);
			this.expectedCookieValue = "";
		}
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		this.csrfTokenRepository.saveToken(exchange, token).block();
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst(this.expectedCookieName);
		assertThat(cookie).isNotNull();
		assertThat(cookie.getMaxAge()).isEqualTo(this.expectedMaxAge);
		assertThat(cookie.getDomain()).isEqualTo(this.expectedDomain);
		assertThat(cookie.getPath()).isEqualTo(this.expectedPath);
		assertThat(cookie.isSecure()).isEqualTo(this.expectedSecure);
		assertThat(cookie.isHttpOnly()).isEqualTo(this.expectedHttpOnly);
		assertThat(cookie.getName()).isEqualTo(this.expectedCookieName);
		assertThat(cookie.getValue()).isEqualTo(this.expectedCookieValue);
		assertThat(cookie.getSameSite()).isEqualTo(this.expectedSameSitePolicy);
	}

	private void generateTokenAndAssertExpectedValues() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		CsrfToken csrfToken = this.csrfTokenRepository.generateToken(exchange).block();
		assertThat(csrfToken).isNotNull();
		assertThat(csrfToken.getHeaderName()).isEqualTo(this.expectedHeaderName);
		assertThat(csrfToken.getParameterName()).isEqualTo(this.expectedParameterName);
		assertThat(csrfToken.getToken()).isNotBlank();
	}

	private CsrfToken createToken() {
		return createToken(this.expectedHeaderName, this.expectedParameterName, this.expectedCookieValue);
	}

	private static CsrfToken createToken(String headerName, String parameterName, String tokenValue) {
		return new DefaultCsrfToken(headerName, parameterName, tokenValue);
	}

	static class MockSslInfo implements SslInfo {

		@Override
		public String getSessionId() {
			return "sessionId";
		}

		@Override
		public X509Certificate[] getPeerCertificates() {
			return new X509Certificate[] {};
		}

	}

}
