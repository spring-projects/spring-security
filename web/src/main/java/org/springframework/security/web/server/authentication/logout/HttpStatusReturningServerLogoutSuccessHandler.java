/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.server.authentication.logout;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.util.Assert;

/**
 * Implementation of the {@link ServerLogoutSuccessHandler}. By default returns an HTTP
 * status code of {@code 200}. This is useful in REST-type scenarios where a redirect upon
 * a successful logout is not desired.
 *
 * @author Eric Deandrea
 * @since 5.1
 */
public class HttpStatusReturningServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {

	private final HttpStatus httpStatusToReturn;

	/**
	 * Initialize the {@code HttpStatusReturningServerLogoutSuccessHandler} with a
	 * user-defined {@link HttpStatus}.
	 * @param httpStatusToReturn Must not be {@code null}.
	 */
	public HttpStatusReturningServerLogoutSuccessHandler(HttpStatus httpStatusToReturn) {
		Assert.notNull(httpStatusToReturn, "The provided HttpStatus must not be null.");
		this.httpStatusToReturn = httpStatusToReturn;
	}

	/**
	 * Initialize the {@code HttpStatusReturningServerLogoutSuccessHandler} with the
	 * default {@link HttpStatus#OK}.
	 */
	public HttpStatusReturningServerLogoutSuccessHandler() {
		this.httpStatusToReturn = HttpStatus.OK;
	}

	/**
	 * Implementation of
	 * {@link ServerLogoutSuccessHandler#onLogoutSuccess(WebFilterExchange, Authentication)}.
	 * Sets the status on the {@link WebFilterExchange}.
	 * @param exchange The exchange
	 * @param authentication The {@link Authentication}
	 * @return A completion notification (success or error)
	 */
	@Override
	public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
		return Mono.fromRunnable(() -> exchange.getExchange().getResponse().setStatusCode(this.httpStatusToReturn));
	}

}
