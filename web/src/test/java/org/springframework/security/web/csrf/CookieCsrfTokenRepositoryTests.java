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

package org.springframework.security.web.csrf;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.web.csrf.CsrfTokenAssert.assertThatCsrfToken;

/**
 * @author Rob Winch
 * @author Alex Montoya
 * @since 4.1
 */
class CookieCsrfTokenRepositoryTests {

	CookieCsrfTokenRepository repository;

	MockHttpServletResponse response;

	MockHttpServletRequest request;

	@BeforeEach
	void setup() {
		this.repository = new CookieCsrfTokenRepository();
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.request.setContextPath("/context");
	}

	@Test
	void generateToken() {
		CsrfToken generateToken = this.repository.generateToken(this.request);
		assertThat(generateToken).isNotNull();
		assertThat(generateToken.getHeaderName()).isEqualTo(CookieCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME);
		assertThat(generateToken.getParameterName()).isEqualTo(CookieCsrfTokenRepository.DEFAULT_CSRF_PARAMETER_NAME);
		assertThat(generateToken.getToken()).isNotEmpty();
	}

	@Test
	void generateTokenCustom() {
		String headerName = "headerName";
		String parameterName = "paramName";
		this.repository.setHeaderName(headerName);
		this.repository.setParameterName(parameterName);
		CsrfToken generateToken = this.repository.generateToken(this.request);
		assertThat(generateToken).isNotNull();
		assertThat(generateToken.getHeaderName()).isEqualTo(headerName);
		assertThat(generateToken.getParameterName()).isEqualTo(parameterName);
		assertThat(generateToken.getToken()).isNotEmpty();
	}

	@Test
	void saveToken() {
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getMaxAge()).isEqualTo(-1);
		assertThat(tokenCookie.getName()).isEqualTo(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getPath()).isEqualTo(this.request.getContextPath());
		assertThat(tokenCookie.getSecure()).isEqualTo(this.request.isSecure());
		assertThat(tokenCookie.getValue()).isEqualTo(token.getToken());
		assertThat(tokenCookie.isHttpOnly()).isTrue();
	}

	// gh-14131
	@Test
	void saveTokenShouldUseResponseAddCookie() {
		CsrfToken token = this.repository.generateToken(this.request);
		MockHttpServletResponse spyResponse = spy(this.response);
		this.repository.saveToken(token, this.request, spyResponse);
		verify(spyResponse).addCookie(any(Cookie.class));
	}

	@Test
	void saveTokenSecure() {
		this.request.setSecure(true);
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getSecure()).isTrue();
	}

	@Test
	void saveTokenSecureFlagTrue() {
		this.request.setSecure(false);
		this.repository.setSecure(Boolean.TRUE);
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getSecure()).isTrue();
	}

	@Test
	void saveTokenSecureFlagTrueUsingCustomizer() {
		this.request.setSecure(false);
		this.repository.setCookieCustomizer((customizer) -> customizer.secure(Boolean.TRUE));
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getSecure()).isTrue();
	}

	@Test
	void saveTokenSecureFlagFalse() {
		this.request.setSecure(true);
		this.repository.setSecure(Boolean.FALSE);
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getSecure()).isFalse();
	}

	@Test
	void saveTokenSecureFlagFalseUsingCustomizer() {
		this.request.setSecure(true);
		this.repository.setCookieCustomizer((customizer) -> customizer.secure(Boolean.FALSE));
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getSecure()).isFalse();
	}

	@Test
	void saveTokenNull() {
		this.request.setSecure(true);
		this.repository.saveToken(null, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getMaxAge()).isZero();
		assertThat(tokenCookie.getName()).isEqualTo(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getPath()).isEqualTo(this.request.getContextPath());
		assertThat(tokenCookie.getSecure()).isEqualTo(this.request.isSecure());
		assertThat(tokenCookie.getValue()).isEmpty();
	}

	@Test
	void saveTokenHttpOnlyTrue() {
		this.repository.setCookieHttpOnly(true);
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.isHttpOnly()).isTrue();
	}

	@Test
	void saveTokenHttpOnlyTrueUsingCustomizer() {
		this.repository.setCookieCustomizer((customizer) -> customizer.httpOnly(true));
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.isHttpOnly()).isTrue();
	}

	@Test
	void saveTokenHttpOnlyFalse() {
		this.repository.setCookieHttpOnly(false);
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.isHttpOnly()).isFalse();
	}

	@Test
	void saveTokenHttpOnlyFalseUsingCustomizer() {
		this.repository.setCookieCustomizer((customizer) -> customizer.httpOnly(false));
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.isHttpOnly()).isFalse();
	}

	@Test
	void saveTokenWithHttpOnlyFalse() {
		this.repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.isHttpOnly()).isFalse();
	}

	@Test
	void saveTokenCustomPath() {
		String customPath = "/custompath";
		this.repository.setCookiePath(customPath);
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getPath()).isEqualTo(this.repository.getCookiePath());
	}

	@Test
	void saveTokenEmptyCustomPath() {
		String customPath = "";
		this.repository.setCookiePath(customPath);
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getPath()).isEqualTo(this.request.getContextPath());
	}

	@Test
	void saveTokenNullCustomPath() {
		String customPath = null;
		this.repository.setCookiePath(customPath);
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getPath()).isEqualTo(this.request.getContextPath());
	}

	@Test
	void saveTokenWithCookieDomain() {
		String domainName = "example.com";
		this.repository.setCookieDomain(domainName);
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getDomain()).isEqualTo(domainName);
	}

	@Test
	void saveTokenWithCookieDomainUsingCustomizer() {
		String domainName = "example.com";
		this.repository.setCookieCustomizer((customizer) -> customizer.domain(domainName));
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getDomain()).isEqualTo(domainName);
	}

	@Test
	void saveTokenWithCookieMaxAge() {
		int maxAge = 1200;
		this.repository.setCookieMaxAge(maxAge);
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getMaxAge()).isEqualTo(maxAge);
	}

	@Test
	void saveTokenWithCookieMaxAgeUsingCustomizer() {
		int maxAge = 1200;
		this.repository.setCookieCustomizer((customizer) -> customizer.maxAge(maxAge));
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getMaxAge()).isEqualTo(maxAge);
	}

	@Test
	void saveTokenWithSameSiteNull() {
		String sameSitePolicy = null;
		this.repository.setCookieCustomizer((customizer) -> customizer.sameSite(sameSitePolicy));
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getAttribute("SameSite")).isNull();
	}

	@Test
	void saveTokenWithSameSiteStrict() {
		String sameSitePolicy = "Strict";
		this.repository.setCookieCustomizer((customizer) -> customizer.sameSite(sameSitePolicy));
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getAttribute("SameSite")).isEqualTo(sameSitePolicy);
	}

	@Test
	void saveTokenWithSameSiteLax() {
		String sameSitePolicy = "Lax";
		this.repository.setCookieCustomizer((customizer) -> customizer.sameSite(sameSitePolicy));
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getAttribute("SameSite")).isEqualTo(sameSitePolicy);
	}

	// gh-13075
	@Test
	void saveTokenWithExistingSetCookieThenDoesNotOverwrite() {
		this.response.setHeader(HttpHeaders.SET_COOKIE, "MyCookie=test");
		this.repository = new CookieCsrfTokenRepository();
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		assertThat(this.response.getCookie("MyCookie")).isNotNull();
		assertThat(this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME)).isNotNull();
	}

	@Test
	void loadTokenNoCookiesNull() {
		assertThat(this.repository.loadToken(this.request)).isNull();
	}

	@Test
	void loadTokenCookieIncorrectNameNull() {
		this.request.setCookies(new Cookie("other", "name"));
		assertThat(this.repository.loadToken(this.request)).isNull();
	}

	@Test
	void loadTokenCookieValueEmptyString() {
		this.request.setCookies(new Cookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, ""));
		assertThat(this.repository.loadToken(this.request)).isNull();
	}

	@Test
	void loadToken() {
		CsrfToken generateToken = this.repository.generateToken(this.request);
		this.request
			.setCookies(new Cookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, generateToken.getToken()));
		CsrfToken loadToken = this.repository.loadToken(this.request);
		assertThat(loadToken).isNotNull();
		assertThat(loadToken.getHeaderName()).isEqualTo(generateToken.getHeaderName());
		assertThat(loadToken.getParameterName()).isEqualTo(generateToken.getParameterName());
		assertThat(loadToken.getToken()).isNotEmpty();
	}

	@Test
	void loadTokenCustom() {
		String cookieName = "cookieName";
		String value = "value";
		String headerName = "headerName";
		String parameterName = "paramName";
		this.repository.setHeaderName(headerName);
		this.repository.setParameterName(parameterName);
		this.repository.setCookieName(cookieName);
		this.request.setCookies(new Cookie(cookieName, value));
		CsrfToken loadToken = this.repository.loadToken(this.request);
		assertThat(loadToken).isNotNull();
		assertThat(loadToken.getHeaderName()).isEqualTo(headerName);
		assertThat(loadToken.getParameterName()).isEqualTo(parameterName);
		assertThat(loadToken.getToken()).isEqualTo(value);
	}

	@Test
	void loadDeferredTokenWhenDoesNotExistThenGeneratedAndSaved() {
		DeferredCsrfToken deferredCsrfToken = this.repository.loadDeferredToken(this.request, this.response);
		CsrfToken csrfToken = deferredCsrfToken.get();
		assertThat(csrfToken).isNotNull();
		assertThat(deferredCsrfToken.isGenerated()).isTrue();
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie).isNotNull();
		assertThat(tokenCookie.getMaxAge()).isEqualTo(-1);
		assertThat(tokenCookie.getName()).isEqualTo(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie.getPath()).isEqualTo(this.request.getContextPath());
		assertThat(tokenCookie.getSecure()).isEqualTo(this.request.isSecure());
		assertThat(tokenCookie.getValue()).isEqualTo(csrfToken.getToken());
		assertThat(tokenCookie.isHttpOnly()).isEqualTo(true);
	}

	@Test
	void loadDeferredTokenWhenExistsAndNullSavedThenGeneratedAndSaved() {
		CsrfToken generatedToken = this.repository.generateToken(this.request);
		this.request
			.setCookies(new Cookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, generatedToken.getToken()));
		this.repository.saveToken(null, this.request, this.response);
		DeferredCsrfToken deferredCsrfToken = this.repository.loadDeferredToken(this.request, this.response);
		CsrfToken csrfToken = deferredCsrfToken.get();
		assertThat(csrfToken).isNotNull();
		assertThat(generatedToken).isNotEqualTo(csrfToken);
		assertThat(deferredCsrfToken.isGenerated()).isTrue();
	}

	@Test
	void loadDeferredTokenWhenExistsAndNullSavedAndNonNullSavedThenLoaded() {
		CsrfToken generatedToken = this.repository.generateToken(this.request);
		this.request
			.setCookies(new Cookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, generatedToken.getToken()));
		this.repository.saveToken(null, this.request, this.response);
		this.repository.saveToken(generatedToken, this.request, this.response);
		DeferredCsrfToken deferredCsrfToken = this.repository.loadDeferredToken(this.request, this.response);
		CsrfToken csrfToken = deferredCsrfToken.get();
		assertThatCsrfToken(csrfToken).isEqualTo(generatedToken);
		assertThat(deferredCsrfToken.isGenerated()).isFalse();
	}

	@Test
	void loadDeferredTokenWhenExistsThenLoaded() {
		CsrfToken generatedToken = this.repository.generateToken(this.request);
		this.request
			.setCookies(new Cookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, generatedToken.getToken()));
		DeferredCsrfToken deferredCsrfToken = this.repository.loadDeferredToken(this.request, this.response);
		CsrfToken csrfToken = deferredCsrfToken.get();
		assertThatCsrfToken(csrfToken).isEqualTo(generatedToken);
		assertThat(deferredCsrfToken.isGenerated()).isFalse();
	}

	@Test
	void cookieCustomizer() {
		String domainName = "example.com";
		String customPath = "/custompath";
		String sameSitePolicy = "Strict";
		this.repository.setCookieCustomizer((customizer) -> {
			customizer.domain(domainName);
			customizer.secure(false);
			customizer.path(customPath);
			customizer.sameSite(sameSitePolicy);
		});
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie).isNotNull();
		assertThat(tokenCookie.getMaxAge()).isEqualTo(-1);
		assertThat(tokenCookie.getDomain()).isEqualTo(domainName);
		assertThat(tokenCookie.getPath()).isEqualTo(customPath);
		assertThat(tokenCookie.isHttpOnly()).isEqualTo(Boolean.TRUE);
		assertThat(tokenCookie.getAttribute("SameSite")).isEqualTo(sameSitePolicy);
	}

	// gh-13659
	@Test
	void withHttpOnlyFalseWhenCookieCustomizerThenStillDefaultsToFalse() {
		CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
		repository.setCookieCustomizer((customizer) -> customizer.maxAge(1000));
		CsrfToken token = repository.generateToken(this.request);
		repository.saveToken(token, this.request, this.response);
		Cookie tokenCookie = this.response.getCookie(CookieCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
		assertThat(tokenCookie).isNotNull();
		assertThat(tokenCookie.getMaxAge()).isEqualTo(1000);
		assertThat(tokenCookie.isHttpOnly()).isEqualTo(Boolean.FALSE);
	}

	// gh-16173
	@Test
	void saveTokenWhenSameSiteAndServletVersion5ThenUsesAddHeader() {
		HttpServletResponse response = mock(HttpServletResponse.class);
		((MockServletContext) this.request.getServletContext()).setMajorVersion(5);
		this.repository.setCookieCustomizer((builder) -> builder.sameSite("Strict"));
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, response);
		verify(response, never()).addCookie(any(Cookie.class));
		verify(response).addHeader(any(), any());
	}

	// gh-16173
	@Test
	void saveTokenWhenSameSiteAndServletVersion6OrHigherThenUsesAddCookie() {
		HttpServletResponse response = mock(HttpServletResponse.class);
		this.repository.setCookieCustomizer((builder) -> builder.sameSite("Strict"));
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, response);
		verify(response).addCookie(any(Cookie.class));
		verify(response, never()).addHeader(any(), any());
	}

	// gh-16173
	@Test
	void saveTokenWhenNoSameSiteThenUsesAddCookie() {
		HttpServletResponse response = mock(HttpServletResponse.class);
		CsrfToken token = this.repository.generateToken(this.request);
		this.repository.saveToken(token, this.request, response);
		verify(response).addCookie(any(Cookie.class));
		verify(response, never()).addHeader(any(), any());
		((MockServletContext) this.request.getServletContext()).setMajorVersion(5);
		response = mock(HttpServletResponse.class);
		this.repository.saveToken(token, this.request, response);
		verify(response).addCookie(any(Cookie.class));
		verify(response, never()).addHeader(any(), any());
	}

	@Test
	void setCookieNameNullIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repository.setCookieName(null));
	}

	@Test
	void setParameterNameNullIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repository.setParameterName(null));
	}

	@Test
	void setHeaderNameNullIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repository.setHeaderName(null));
	}

	@Test
	void setCookieMaxAgeZeroIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repository.setCookieMaxAge(0));
	}

}
