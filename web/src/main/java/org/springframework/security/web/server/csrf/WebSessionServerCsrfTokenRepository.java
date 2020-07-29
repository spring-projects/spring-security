/*
 * Copyright 2002-2017 the original author or authors.
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

import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * A {@link ServerCsrfTokenRepository} that stores the {@link CsrfToken} in the
 * {@link HttpSession}.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class WebSessionServerCsrfTokenRepository implements ServerCsrfTokenRepository {

	private static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";

	private static final String DEFAULT_CSRF_HEADER_NAME = "X-CSRF-TOKEN";

	private static final String DEFAULT_CSRF_TOKEN_ATTR_NAME = WebSessionServerCsrfTokenRepository.class.getName()
			.concat(".CSRF_TOKEN");

	private String parameterName = DEFAULT_CSRF_PARAMETER_NAME;

	private String headerName = DEFAULT_CSRF_HEADER_NAME;

	private String sessionAttributeName = DEFAULT_CSRF_TOKEN_ATTR_NAME;

	@Override
	public Mono<CsrfToken> generateToken(ServerWebExchange exchange) {
		Mono.just(exchange).publishOn(Schedulers.boundedElastic());
		return Mono.fromCallable(() -> createCsrfToken());
	}

	@Override
	public Mono<Void> saveToken(ServerWebExchange exchange, CsrfToken token) {
		return exchange.getSession().doOnNext(session -> putToken(session.getAttributes(), token))
				.flatMap(session -> session.changeSessionId());
	}

	private void putToken(Map<String, Object> attributes, CsrfToken token) {
		if (token == null) {
			attributes.remove(this.sessionAttributeName);
		}
		else {
			attributes.put(this.sessionAttributeName, token);
		}
	}

	@Override
	public Mono<CsrfToken> loadToken(ServerWebExchange exchange) {
		return exchange.getSession().filter(s -> s.getAttributes().containsKey(this.sessionAttributeName))
				.map(s -> s.getAttribute(this.sessionAttributeName));
	}

	/**
	 * Sets the {@link HttpServletRequest} parameter name that the {@link CsrfToken} is
	 * expected to appear on
	 * @param parameterName the new parameter name to use
	 */
	public void setParameterName(String parameterName) {
		Assert.hasLength(parameterName, "parameterName cannot be null or empty");
		this.parameterName = parameterName;
	}

	/**
	 * Sets the header name that the {@link CsrfToken} is expected to appear on and the
	 * header that the response will contain the {@link CsrfToken}.
	 * @param headerName the new header name to use
	 */
	public void setHeaderName(String headerName) {
		Assert.hasLength(headerName, "headerName cannot be null or empty");
		this.headerName = headerName;
	}

	/**
	 * Sets the {@link HttpSession} attribute name that the {@link CsrfToken} is stored in
	 * @param sessionAttributeName the new attribute name to use
	 */
	public void setSessionAttributeName(String sessionAttributeName) {
		Assert.hasLength(sessionAttributeName, "sessionAttributename cannot be null or empty");
		this.sessionAttributeName = sessionAttributeName;
	}

	private CsrfToken createCsrfToken() {
		return new DefaultCsrfToken(this.headerName, this.parameterName, createNewToken());
	}

	private String createNewToken() {
		return UUID.randomUUID().toString();
	}

}
