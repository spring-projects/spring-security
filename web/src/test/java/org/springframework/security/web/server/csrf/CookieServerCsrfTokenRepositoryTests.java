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

package org.springframework.security.web.server.csrf;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.function.Supplier;

import org.junit.Test;

import org.springframework.http.ResponseCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * @author Eric Deandrea
 * @since 5.1
 */
public class CookieServerCsrfTokenRepositoryTests {
	@Test
	public void generateTokenDefault() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/someUri"));
		CookieServerCsrfTokenRepository csrfTokenRepository =
			CookieServerCsrfTokenRepositoryFactory.createRepository(CookieServerCsrfTokenRepository::new);
		Mono<CsrfToken> csrfTokenMono = csrfTokenRepository.generateToken(exchange);

		assertThat(csrfTokenMono).isNotNull();
		assertThat(csrfTokenMono.block())
			.isNotNull()
			.extracting("headerName", "parameterName")
			.containsExactly(CookieServerCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME, CookieServerCsrfTokenRepository.DEFAULT_CSRF_PARAMETER_NAME);
		assertThat(csrfTokenMono.block().getToken()).isNotBlank();
	}

	@Test
	public void generateTokenChangeHeaderName() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/someUri"));
		CookieServerCsrfTokenRepository csrfTokenRepository =
			CookieServerCsrfTokenRepositoryFactory.createRepository(CookieServerCsrfTokenRepository::new,
				CookieServerCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME,
				"someHeader",
				CookieServerCsrfTokenRepository.DEFAULT_CSRF_PARAMETER_NAME);
		Mono<CsrfToken> csrfTokenMono = csrfTokenRepository.generateToken(exchange);

		assertThat(csrfTokenMono).isNotNull();
		assertThat(csrfTokenMono.block())
			.isNotNull()
			.extracting("headerName", "parameterName")
			.containsExactly("someHeader", CookieServerCsrfTokenRepository.DEFAULT_CSRF_PARAMETER_NAME);
		assertThat(csrfTokenMono.block().getToken()).isNotBlank();
	}

	@Test
	public void generateTokenChangeParameterName() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/someUri"));
		CookieServerCsrfTokenRepository csrfTokenRepository =
			CookieServerCsrfTokenRepositoryFactory.createRepository(CookieServerCsrfTokenRepository::new,
				CookieServerCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME,
				CookieServerCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME,
				"someParam");
		Mono<CsrfToken> csrfTokenMono = csrfTokenRepository.generateToken(exchange);

		assertThat(csrfTokenMono).isNotNull();
		assertThat(csrfTokenMono.block())
			.isNotNull()
			.extracting("headerName", "parameterName")
			.containsExactly(CookieServerCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME, "someParam");
		assertThat(csrfTokenMono.block().getToken()).isNotBlank();
	}

	@Test
	public void generateTokenChangeHeaderAndParameterName() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/someUri"));
		CookieServerCsrfTokenRepository csrfTokenRepository =
			CookieServerCsrfTokenRepositoryFactory.createRepository(CookieServerCsrfTokenRepository::new,
				CookieServerCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME,
				"someHeader",
				"someParam");
		Mono<CsrfToken> csrfTokenMono = csrfTokenRepository.generateToken(exchange);

		assertThat(csrfTokenMono).isNotNull();
		assertThat(csrfTokenMono.block())
			.isNotNull()
			.extracting("headerName", "parameterName")
			.containsExactly("someHeader", "someParam");
		assertThat(csrfTokenMono.block().getToken()).isNotBlank();
	}

	@Test
	public void saveTokenDefault() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/someUri"));
		CookieServerCsrfTokenRepository csrfTokenRepository =
			CookieServerCsrfTokenRepositoryFactory.createRepository(CookieServerCsrfTokenRepository::new);

		Mono<Void> csrfTokenMono = csrfTokenRepository.saveToken(exchange, createToken("someTokenValue"));
		ResponseCookie cookie = exchange
			.getResponse()
			.getCookies()
			.getFirst(CookieServerCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);

		assertThat(csrfTokenMono).isNotNull();
		assertThat(cookie)
			.isNotNull()
			.extracting("maxAge", "domain", "path", "secure", "httpOnly", "name", "value")
			.containsExactly(Duration.ofSeconds(-1), null, "/", false, true, "XSRF-TOKEN", "someTokenValue");
	}

	@Test
	public void saveTokenMaxAge() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/someUri"));
		CookieServerCsrfTokenRepository csrfTokenRepository =
			CookieServerCsrfTokenRepositoryFactory.createRepository(CookieServerCsrfTokenRepository::new);

		Mono<Void> csrfTokenMono = csrfTokenRepository.saveToken(exchange, null);
		ResponseCookie cookie = exchange
			.getResponse()
			.getCookies()
			.getFirst(CookieServerCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);

		assertThat(csrfTokenMono).isNotNull();
		assertThat(cookie)
			.isNotNull()
			.extracting("maxAge", "domain", "path", "secure", "httpOnly", "name", "value")
			.containsExactly(Duration.ofSeconds(0), null, "/", false, true, "XSRF-TOKEN", "");
	}

	@Test
	public void saveTokenHttpOnly() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/someUri"));
		CookieServerCsrfTokenRepository csrfTokenRepository =
			CookieServerCsrfTokenRepositoryFactory.createRepository(CookieServerCsrfTokenRepository::withHttpOnlyFalse);

		Mono<Void> csrfTokenMono = csrfTokenRepository.saveToken(exchange, createToken("someTokenValue"));
		ResponseCookie cookie = exchange
			.getResponse()
			.getCookies()
			.getFirst(CookieServerCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);

		assertThat(csrfTokenMono).isNotNull();
		assertThat(cookie)
			.isNotNull()
			.extracting("maxAge", "domain", "path", "secure", "httpOnly", "name", "value")
			.containsExactly(Duration.ofSeconds(-1), null, "/", false, false, "XSRF-TOKEN", "someTokenValue");
	}

	@Test
	public void saveTokenOverriddenViaCsrfProps() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/someUri"));
		CookieServerCsrfTokenRepository csrfTokenRepository =
			CookieServerCsrfTokenRepositoryFactory.createRepository(CookieServerCsrfTokenRepository::new,
			".spring.io",  "csrfCookie", "/some/path",
				"headerName", "paramName");

		Mono<Void> csrfTokenMono =
			csrfTokenRepository.saveToken(exchange, createToken("headerName", "paramName", "someTokenValue"));
		ResponseCookie cookie = exchange.getResponse().getCookies().getFirst("csrfCookie");

		assertThat(csrfTokenMono).isNotNull();
		assertThat(cookie)
			.isNotNull()
			.extracting("maxAge", "domain", "path", "secure", "httpOnly", "name", "value")
			.containsExactly(Duration.ofSeconds(-1), ".spring.io", "/some/path", false, true, "csrfCookie", "someTokenValue");
	}

	@Test
	public void loadTokenThatExists() {
		MockServerWebExchange exchange = MockServerWebExchange.from(
			MockServerHttpRequest.post("/someUri")
				.cookie(ResponseCookie.from(CookieServerCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "someTokenValue").build()));

		CookieServerCsrfTokenRepository csrfTokenRepository =
			CookieServerCsrfTokenRepositoryFactory.createRepository(CookieServerCsrfTokenRepository::new);
		Mono<CsrfToken> csrfTokenMono = csrfTokenRepository.loadToken(exchange);

		assertThat(csrfTokenMono).isNotNull();
		assertThat(csrfTokenMono.block())
			.isNotNull()
			.extracting("headerName", "parameterName", "token")
			.containsExactly(
				CookieServerCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME,
				CookieServerCsrfTokenRepository.DEFAULT_CSRF_PARAMETER_NAME,
				"someTokenValue");
	}

	@Test
	public void loadTokenThatDoesntExists() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/someUri"));
		CookieServerCsrfTokenRepository csrfTokenRepository =
			CookieServerCsrfTokenRepositoryFactory.createRepository(CookieServerCsrfTokenRepository::new);

		Mono<CsrfToken> csrfTokenMono = csrfTokenRepository.loadToken(exchange);
		assertThat(csrfTokenMono).isNotNull();
		assertThat(csrfTokenMono.block()).isNull();
	}

	private static CsrfToken createToken(String tokenValue) {
		return createToken(CookieServerCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME,
			CookieServerCsrfTokenRepository.DEFAULT_CSRF_PARAMETER_NAME, tokenValue);
	}

	private static CsrfToken createToken(String headerName, String parameterName, String tokenValue) {
		return new DefaultCsrfToken(headerName, parameterName, tokenValue);
	}

	static final class CookieServerCsrfTokenRepositoryFactory {
		private CookieServerCsrfTokenRepositoryFactory() {
			super();
		}

		static CookieServerCsrfTokenRepository createRepository(Supplier<CookieServerCsrfTokenRepository> cookieServerCsrfTokenRepositorySupplier) {
			return createRepository(cookieServerCsrfTokenRepositorySupplier,
				CookieServerCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME,
				CookieServerCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME,
				CookieServerCsrfTokenRepository.DEFAULT_CSRF_PARAMETER_NAME);
		}

		static CookieServerCsrfTokenRepository createRepository(
			Supplier<CookieServerCsrfTokenRepository> cookieServerCsrfTokenRepositorySupplier,
			String cookieName, String headerName, String parameterName) {

			return createRepository(cookieServerCsrfTokenRepositorySupplier,
				null, cookieName, null, headerName, parameterName);
		}

		static CookieServerCsrfTokenRepository createRepository(
			Supplier<CookieServerCsrfTokenRepository> cookieServerCsrfTokenRepositorySupplier,
			String cookieDomain, String cookieName, String cookiePath, String headerName, String parameterName) {

			return cookieServerCsrfTokenRepositorySupplier.get()
				.withCookieDomain(cookieDomain)
				.withCookieName(cookieName)
				.withCookiePath(cookiePath)
				.withHeaderName(headerName)
				.withParameterName(parameterName);
		}
	}
}