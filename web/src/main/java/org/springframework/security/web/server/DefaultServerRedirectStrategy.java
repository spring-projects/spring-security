/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.web.server;

import java.net.URI;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * The default {@link ServerRedirectStrategy} to use.
 *
 * @author Rob Winch
 * @author Mathieu Ouellet
 * @since 5.0
 */
public class DefaultServerRedirectStrategy implements ServerRedirectStrategy {

	private static final Log logger = LogFactory.getLog(DefaultServerRedirectStrategy.class);

	private HttpStatus httpStatus = HttpStatus.FOUND;

	private boolean contextRelative = true;

	@Override
	public Mono<Void> sendRedirect(ServerWebExchange exchange, URI location) {
		Assert.notNull(exchange, "exchange cannot be null");
		Assert.notNull(location, "location cannot be null");
		return Mono.fromRunnable(() -> {
			ServerHttpResponse response = exchange.getResponse();
			response.setStatusCode(this.httpStatus);
			URI newLocation = createLocation(exchange, location);
			if (logger.isDebugEnabled()) {
				logger.debug("Redirecting to '" + newLocation + "'");
			}
			response.getHeaders().setLocation(newLocation);
		});
	}

	private URI createLocation(ServerWebExchange exchange, URI location) {
		if (!this.contextRelative) {
			return location;
		}
		String url = location.toASCIIString();
		if (url.startsWith("/")) {
			String context = exchange.getRequest().getPath().contextPath().value();
			return URI.create(context + url);
		}
		return location;
	}

	/**
	 * The {@link HttpStatus} to use for the redirect.
	 * @param httpStatus the status to use. Cannot be null
	 */
	public void setHttpStatus(HttpStatus httpStatus) {
		Assert.notNull(httpStatus, "httpStatus cannot be null");
		this.httpStatus = httpStatus;
	}

	/**
	 * Sets if the location is relative to the context.
	 * @param contextRelative if redirects should be relative to the context. Default is
	 * true.
	 */
	public void setContextRelative(boolean contextRelative) {
		this.contextRelative = contextRelative;
	}

}
