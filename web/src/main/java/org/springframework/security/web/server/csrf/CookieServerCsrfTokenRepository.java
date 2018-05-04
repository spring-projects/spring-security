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

import java.util.Optional;
import java.util.UUID;

import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * A {@link ServerCsrfTokenRepository} that persists the CSRF token in a cookie named "XSRF-TOKEN" and
 * reads from the header "X-XSRF-TOKEN" following the conventions of AngularJS. When using with
 * AngularJS be sure to use {@link #withHttpOnlyFalse()} .
 *
 * @author Eric Deandrea
 * @since 5.1
 */
public final class CookieServerCsrfTokenRepository implements ServerCsrfTokenRepository {
	static final String DEFAULT_CSRF_COOKIE_NAME = "XSRF-TOKEN";
	static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";
	static final String DEFAULT_CSRF_HEADER_NAME = "X-XSRF-TOKEN";

	private String parameterName = DEFAULT_CSRF_PARAMETER_NAME;
	private String headerName = DEFAULT_CSRF_HEADER_NAME;
	private String cookiePath;
	private String cookieDomain;
	private String cookieName = DEFAULT_CSRF_COOKIE_NAME;
	private boolean cookieHttpOnly = true;

	/**
	 * Factory method to conveniently create an instance that has
	 * {@link #setCookieHttpOnly(boolean)} set to false.
	 *
	 * @return an instance of CookieCsrfTokenRepository with
	 * {@link #setCookieHttpOnly(boolean)} set to false
	 */
	public static CookieServerCsrfTokenRepository withHttpOnlyFalse() {
		return new CookieServerCsrfTokenRepository().withCookieHttpOnly(false);
	}

	@Override
	public Mono<CsrfToken> generateToken(ServerWebExchange exchange) {
		return Mono.fromCallable(this::createCsrfToken);
	}

	@Override
	public Mono<Void> saveToken(ServerWebExchange exchange, CsrfToken token) {
		Optional<String> tokenValue = Optional.ofNullable(token).map(CsrfToken::getToken);

		ResponseCookie cookie = ResponseCookie.from(this.cookieName, tokenValue.orElse(""))
			.domain(this.cookieDomain)
			.httpOnly(this.cookieHttpOnly)
			.maxAge(tokenValue.map(val -> -1).orElse(0))
			.path(Optional.ofNullable(this.cookiePath).orElseGet(() -> getRequestContext(exchange.getRequest())))
			.secure(Optional.ofNullable(exchange.getRequest().getSslInfo()).map(sslInfo -> true).orElse(false))
			.build();

		exchange.getResponse().addCookie(cookie);

		return Mono.empty();
	}

	@Override
	public Mono<CsrfToken> loadToken(ServerWebExchange exchange) {
		Optional<CsrfToken> token = Optional.ofNullable(exchange.getRequest())
			.map(ServerHttpRequest::getCookies)
			.map(cookiesMap -> cookiesMap.getFirst(this.cookieName))
			.map(HttpCookie::getValue)
			.map(this::createCsrfToken);

		return Mono.justOrEmpty(token);
	}

	/**
	 * Sets the HttpOnly attribute on the cookie containing the CSRF token
	 * @param cookieHttpOnly True to mark the cookie as http only. False otherwise.
	 */
	public void setCookieHttpOnly(boolean cookieHttpOnly) {
		this.cookieHttpOnly = cookieHttpOnly;
	}

	/**
	 * Sets the HttpOnly attribute on the cookie containing the CSRF token
	 * @param cookieHttpOnly True to mark the cookie as http only. False otherwise.
	 * @return This instance
	 */
	public CookieServerCsrfTokenRepository withCookieHttpOnly(boolean cookieHttpOnly) {
		setCookieHttpOnly(cookieHttpOnly);
		return this;
	}

	/**
	 * Sets the cookie name
	 * @param cookieName The cookie name
	 */
	public void setCookieName(String cookieName) {
		Assert.hasLength(cookieName, "cookieName can't be null");
		this.cookieName = cookieName;
	}

	/**
	 * Sets the cookie name
	 * @param cookieName The cookie name
	 * @return This instance
	 */
	public CookieServerCsrfTokenRepository withCookieName(String cookieName) {
		setCookieName(cookieName);
		return this;
	}

	/**
	 * Sets the parameter name
	 * @param parameterName The parameter name
	 */
	public void setParameterName(String parameterName) {
		Assert.hasLength(parameterName, "parameterName can't be null");
		this.parameterName = parameterName;
	}

	/**
	 * Sets the parameter name
	 * @param parameterName The parameter name
	 * @return This instance
	 */
	public CookieServerCsrfTokenRepository withParameterName(String parameterName) {
		setParameterName(parameterName);
		return this;
	}

	/**
	 * Sets the header name
	 * @param headerName The header name
	 * @return This instance
	 */
	public void setHeaderName(String headerName) {
		Assert.hasLength(headerName, "headerName can't be null");
		this.headerName = headerName;
	}

	/**
	 * Sets the header name
	 * @param headerName The header name
	 * @return This instance
	 */
	public CookieServerCsrfTokenRepository withHeaderName(String headerName) {
		setHeaderName(headerName);
		return this;
	}

	/**
	 * Sets the cookie path
	 * @param cookiePath The cookie path
	 * @return This instance
	 */
	public void setCookiePath(String cookiePath) {
		this.cookiePath = cookiePath;
	}

	/**
	 * Sets the cookie path
	 * @param cookiePath The cookie path
	 * @return This instance
	 */
	public CookieServerCsrfTokenRepository withCookiePath(String cookiePath) {
		setCookiePath(cookiePath);
		return this;
	}

	/**
	 * Sets the cookie domain
	 * @param cookieDomain The cookie domain
	 * @return This instance
	 */
	public void setCookieDomain(String cookieDomain) {
		this.cookieDomain = cookieDomain;
	}

	/**
	 * Sets the cookie domain
	 * @param cookieDomain The cookie domain
	 * @return This instance
	 */
	public CookieServerCsrfTokenRepository withCookieDomain(String cookieDomain) {
		setCookieDomain(cookieDomain);
		return this;
	}

	private CsrfToken createCsrfToken() {
		return createCsrfToken(createNewToken());
	}

	private CsrfToken createCsrfToken(String tokenValue) {
		return new DefaultCsrfToken(this.headerName, this.parameterName, tokenValue);
	}

	private String createNewToken() {
		return UUID.randomUUID().toString();
	}

	private String getRequestContext(ServerHttpRequest request) {
		return Optional.ofNullable(request)
			.map(ServerHttpRequest::getPath)
			.map(RequestPath::contextPath)
			.map(PathContainer::value)
			.filter(contextPath -> contextPath.length() > 0)
			.orElse("/");
	}
}
