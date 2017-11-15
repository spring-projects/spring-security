/*
 * Copyright 2002-2017 the original author or authors.
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

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Map;
import java.util.UUID;

/**
 * A {@link ServerCsrfTokenRepository} that stores the {@link CsrfToken} in the
 * {@link HttpSession}.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class WebSessionServerCsrfTokenRepository
	implements ServerCsrfTokenRepository {
	private static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";

	private static final String DEFAULT_CSRF_HEADER_NAME = "X-CSRF-TOKEN";

	private static final String DEFAULT_CSRF_TOKEN_ATTR_NAME = WebSessionServerCsrfTokenRepository.class
			.getName().concat(".CSRF_TOKEN");

	private String parameterName = DEFAULT_CSRF_PARAMETER_NAME;

	private String headerName = DEFAULT_CSRF_HEADER_NAME;

	private String sessionAttributeName = DEFAULT_CSRF_TOKEN_ATTR_NAME;

	@Override
	public Mono<CsrfToken> generateToken(ServerWebExchange exchange) {
		return exchange.getSession()
			.map(WebSession::getAttributes)
			.map(this::createCsrfToken);
	}

	@Override
	public Mono<CsrfToken> saveToken(ServerWebExchange exchange, CsrfToken token) {
		if(token != null) {
			return Mono.just(token);
		}
		return exchange.getSession()
			.map(WebSession::getAttributes)
			.flatMap( attrs -> save(attrs, token));
	}

	private Mono<CsrfToken> save(Map<String, Object> attributes, CsrfToken token) {
		return Mono.defer(() -> {
			putToken(attributes, token);
			return Mono.justOrEmpty(token);
		});
	}

	private void putToken(Map<String, Object> attributes, CsrfToken token) {
		if(token == null) {
			attributes.remove(this.sessionAttributeName);
		} else {
			attributes.put(this.sessionAttributeName, token);
		}
	}

	@Override
	public Mono<CsrfToken> loadToken(ServerWebExchange exchange) {
		return exchange.getSession()
			.filter( s -> s.getAttributes().containsKey(this.sessionAttributeName))
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
	 *
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
		Assert.hasLength(sessionAttributeName,
				"sessionAttributename cannot be null or empty");
		this.sessionAttributeName = sessionAttributeName;
	}


	private CsrfToken createCsrfToken(Map<String, Object> attributes) {
		return new LazyCsrfToken(attributes, createCsrfToken());
	}

	private CsrfToken createCsrfToken() {
		return new DefaultCsrfToken(this.headerName, this.parameterName, createNewToken());
	}

	private String createNewToken() {
		return UUID.randomUUID().toString();
	}

	private class LazyCsrfToken implements CsrfToken {
		private final Map<String, Object> attributes;
		private final CsrfToken delegate;

		private LazyCsrfToken(Map<String, Object> attributes, CsrfToken delegate) {
			this.attributes = attributes;
			this.delegate = delegate;
		}

		@Override
		public String getHeaderName() {
			return this.delegate.getHeaderName();
		}

		@Override
		public String getParameterName() {
			return this.delegate.getParameterName();
		}

		@Override
		public String getToken() {
			putToken(this.attributes, this.delegate);
			return this.delegate.getToken();
		}

		@Override
		public boolean equals(Object o) {
			if (this == o)
				return true;
			if (o == null || !(o instanceof CsrfToken))
				return false;

			CsrfToken that = (CsrfToken) o;

			if (!getToken().equals(that.getToken()))
				return false;
			if (!getParameterName().equals(that.getParameterName()))
				return false;
			return getHeaderName().equals(that.getHeaderName());
		}

		@Override
		public int hashCode() {
			int result = getToken().hashCode();
			result = 31 * result + getParameterName().hashCode();
			result = 31 * result + getHeaderName().hashCode();
			return result;
		}

		@Override
		public String toString() {
			return "LazyCsrfToken{" + "delegate=" + this.delegate + '}';
		}
	}
}
