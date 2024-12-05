/*
 * Copyright 2012-2024 the original author or authors.
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

import java.util.UUID;
import java.util.function.Consumer;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.WebUtils;

/**
 * A {@link CsrfTokenRepository} that persists the CSRF token in a cookie named
 * "XSRF-TOKEN" and reads from the header "X-XSRF-TOKEN" following the conventions of
 * AngularJS. When using with AngularJS be sure to use {@link #withHttpOnlyFalse()}.
 *
 * @author Rob Winch
 * @author Steve Riesenberg
 * @author Alex Montoya
 * @since 4.1
 */
public final class CookieCsrfTokenRepository implements CsrfTokenRepository {

	static final String DEFAULT_CSRF_COOKIE_NAME = "XSRF-TOKEN";

	static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";

	static final String DEFAULT_CSRF_HEADER_NAME = "X-XSRF-TOKEN";

	private static final String CSRF_TOKEN_REMOVED_ATTRIBUTE_NAME = CookieCsrfTokenRepository.class.getName()
		.concat(".REMOVED");

	private String parameterName = DEFAULT_CSRF_PARAMETER_NAME;

	private String headerName = DEFAULT_CSRF_HEADER_NAME;

	private String cookieName = DEFAULT_CSRF_COOKIE_NAME;

	private boolean cookieHttpOnly = true;

	private String cookiePath;

	private String cookieDomain;

	private Boolean secure;

	private int cookieMaxAge = -1;

	private Consumer<ResponseCookie.ResponseCookieBuilder> cookieCustomizer = (builder) -> {
	};

	/**
	 * Add a {@link Consumer} for a {@code ResponseCookieBuilder} that will be invoked for
	 * each cookie being built, just before the call to {@code build()}.
	 * @param cookieCustomizer consumer for a cookie builder
	 * @since 6.1
	 */
	public void setCookieCustomizer(Consumer<ResponseCookie.ResponseCookieBuilder> cookieCustomizer) {
		Assert.notNull(cookieCustomizer, "cookieCustomizer must not be null");
		this.cookieCustomizer = cookieCustomizer;
	}

	@Override
	public CsrfToken generateToken(HttpServletRequest request) {
		return new DefaultCsrfToken(this.headerName, this.parameterName, createNewToken());
	}

	@Override
	public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
		String tokenValue = (token != null) ? token.getToken() : "";

		ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(this.cookieName, tokenValue)
			.secure((this.secure != null) ? this.secure : request.isSecure())
			.path(StringUtils.hasLength(this.cookiePath) ? this.cookiePath : this.getRequestContext(request))
			.maxAge((token != null) ? this.cookieMaxAge : 0)
			.httpOnly(this.cookieHttpOnly)
			.domain(this.cookieDomain);

		this.cookieCustomizer.accept(cookieBuilder);

		ResponseCookie responseCookie = cookieBuilder.build();
		if (!StringUtils.hasLength(responseCookie.getSameSite())) {
			Cookie cookie = mapToCookie(responseCookie);
			response.addCookie(cookie);
		}
		else if (request.getServletContext().getMajorVersion() > 5) {
			Cookie cookie = mapToCookie(responseCookie);
			response.addCookie(cookie);
		}
		else {
			response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
		}

		// Set request attribute to signal that response has blank cookie value,
		// which allows loadToken to return null when token has been removed
		if (!StringUtils.hasLength(tokenValue)) {
			request.setAttribute(CSRF_TOKEN_REMOVED_ATTRIBUTE_NAME, Boolean.TRUE);
		}
		else {
			request.removeAttribute(CSRF_TOKEN_REMOVED_ATTRIBUTE_NAME);
		}
	}

	@Override
	public CsrfToken loadToken(HttpServletRequest request) {
		// Return null when token has been removed during the current request
		// which allows loadDeferredToken to re-generate the token
		if (Boolean.TRUE.equals(request.getAttribute(CSRF_TOKEN_REMOVED_ATTRIBUTE_NAME))) {
			return null;
		}
		Cookie cookie = WebUtils.getCookie(request, this.cookieName);
		if (cookie == null) {
			return null;
		}
		String token = cookie.getValue();
		if (!StringUtils.hasLength(token)) {
			return null;
		}
		return new DefaultCsrfToken(this.headerName, this.parameterName, token);
	}

	/**
	 * Sets the name of the HTTP request parameter that should be used to provide a token.
	 * @param parameterName the name of the HTTP request parameter that should be used to
	 * provide a token
	 */
	public void setParameterName(String parameterName) {
		Assert.notNull(parameterName, "parameterName cannot be null");
		this.parameterName = parameterName;
	}

	/**
	 * Sets the name of the HTTP header that should be used to provide the token.
	 * @param headerName the name of the HTTP header that should be used to provide the
	 * token
	 */
	public void setHeaderName(String headerName) {
		Assert.notNull(headerName, "headerName cannot be null");
		this.headerName = headerName;
	}

	/**
	 * Sets the name of the cookie that the expected CSRF token is saved to and read from.
	 * @param cookieName the name of the cookie that the expected CSRF token is saved to
	 * and read from
	 */
	public void setCookieName(String cookieName) {
		Assert.notNull(cookieName, "cookieName cannot be null");
		this.cookieName = cookieName;
	}

	/**
	 * @deprecated Use {@link #setCookieCustomizer(Consumer)} instead.
	 */
	@Deprecated(since = "6.1")
	public void setCookieHttpOnly(boolean cookieHttpOnly) {
		this.cookieHttpOnly = cookieHttpOnly;
	}

	private String getRequestContext(HttpServletRequest request) {
		String contextPath = request.getContextPath();
		return (contextPath.length() > 0) ? contextPath : "/";
	}

	/**
	 * Factory method to conveniently create an instance that creates cookies where
	 * {@link Cookie#isHttpOnly()} is set to false.
	 * @return an instance of CookieCsrfTokenRepository that creates cookies where
	 * {@link Cookie#isHttpOnly()} is set to false.
	 */
	public static CookieCsrfTokenRepository withHttpOnlyFalse() {
		CookieCsrfTokenRepository result = new CookieCsrfTokenRepository();
		result.cookieHttpOnly = false;
		return result;
	}

	private String createNewToken() {
		return UUID.randomUUID().toString();
	}

	private Cookie mapToCookie(ResponseCookie responseCookie) {
		Cookie cookie = new Cookie(responseCookie.getName(), responseCookie.getValue());
		cookie.setSecure(responseCookie.isSecure());
		cookie.setPath(responseCookie.getPath());
		cookie.setMaxAge((int) responseCookie.getMaxAge().getSeconds());
		cookie.setHttpOnly(responseCookie.isHttpOnly());
		if (StringUtils.hasLength(responseCookie.getDomain())) {
			cookie.setDomain(responseCookie.getDomain());
		}
		if (StringUtils.hasText(responseCookie.getSameSite())) {
			cookie.setAttribute("SameSite", responseCookie.getSameSite());
		}
		return cookie;
	}

	/**
	 * Set the path that the Cookie will be created with. This will override the default
	 * functionality which uses the request context as the path.
	 * @param path the path to use
	 */
	public void setCookiePath(String path) {
		this.cookiePath = path;
	}

	/**
	 * Get the path that the CSRF cookie will be set to.
	 * @return the path to be used.
	 */
	public String getCookiePath() {
		return this.cookiePath;
	}

	/**
	 * @since 5.2
	 * @deprecated Use {@link #setCookieCustomizer(Consumer)} instead.
	 */
	@Deprecated(since = "6.1")
	public void setCookieDomain(String cookieDomain) {
		this.cookieDomain = cookieDomain;
	}

	/**
	 * @since 5.4
	 * @deprecated Use {@link #setCookieCustomizer(Consumer)} instead.
	 */
	@Deprecated(since = "6.1")
	public void setSecure(Boolean secure) {
		this.secure = secure;
	}

	/**
	 * @since 5.5
	 * @deprecated Use {@link #setCookieCustomizer(Consumer)} instead.
	 */
	@Deprecated(since = "6.1")
	public void setCookieMaxAge(int cookieMaxAge) {
		Assert.isTrue(cookieMaxAge != 0, "cookieMaxAge cannot be zero");
		this.cookieMaxAge = cookieMaxAge;
	}

}
