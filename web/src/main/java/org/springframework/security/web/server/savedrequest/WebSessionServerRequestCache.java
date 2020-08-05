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

package org.springframework.security.web.server.savedrequest;

import java.net.URI;
import java.util.Collections;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.web.server.util.matcher.AndServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

/**
 * An implementation of {@link ServerRequestCache} that saves the
 * {@link ServerHttpRequest} in the {@link WebSession}.
 *
 * The current implementation only saves the URL that was requested.
 *
 * @author Rob Winch
 * @author Mathieu Ouellet
 * @since 5.0
 */
public class WebSessionServerRequestCache implements ServerRequestCache {

	private static final String DEFAULT_SAVED_REQUEST_ATTR = "SPRING_SECURITY_SAVED_REQUEST";

	private static final Log logger = LogFactory.getLog(WebSessionServerRequestCache.class);

	private String sessionAttrName = DEFAULT_SAVED_REQUEST_ATTR;

	private ServerWebExchangeMatcher saveRequestMatcher = createDefaultRequestMacher();

	/**
	 * Sets the matcher to determine if the request should be saved. The default is to
	 * match on any GET request.
	 * @param saveRequestMatcher
	 */
	public void setSaveRequestMatcher(ServerWebExchangeMatcher saveRequestMatcher) {
		Assert.notNull(saveRequestMatcher, "saveRequestMatcher cannot be null");
		this.saveRequestMatcher = saveRequestMatcher;
	}

	@Override
	public Mono<Void> saveRequest(ServerWebExchange exchange) {
		return this.saveRequestMatcher.matches(exchange).filter(MatchResult::isMatch)
				.flatMap(m -> exchange.getSession()).map(WebSession::getAttributes).doOnNext(attrs -> {
					String requestPath = pathInApplication(exchange.getRequest());
					attrs.put(this.sessionAttrName, requestPath);
					if (logger.isDebugEnabled()) {
						logger.debug("Request added to WebSession: '" + requestPath + "'");
					}
				}).then();
	}

	@Override
	public Mono<URI> getRedirectUri(ServerWebExchange exchange) {
		return exchange.getSession()
				.flatMap(session -> Mono.justOrEmpty(session.<String>getAttribute(this.sessionAttrName)))
				.map(URI::create);
	}

	@Override
	public Mono<ServerHttpRequest> removeMatchingRequest(ServerWebExchange exchange) {
		return exchange.getSession().map(WebSession::getAttributes).filter(attributes -> {
			String requestPath = pathInApplication(exchange.getRequest());
			boolean removed = attributes.remove(this.sessionAttrName, requestPath);
			if (removed) {
				if (logger.isDebugEnabled()) {
					logger.debug("Request removed from WebSession: '" + requestPath + "'");
				}
			}
			return removed;
		}).map(attributes -> exchange.getRequest());
	}

	private static String pathInApplication(ServerHttpRequest request) {
		String path = request.getPath().pathWithinApplication().value();
		String query = request.getURI().getRawQuery();
		return path + (query != null ? "?" + query : "");
	}

	private static ServerWebExchangeMatcher createDefaultRequestMacher() {
		ServerWebExchangeMatcher get = ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/**");
		ServerWebExchangeMatcher notFavicon = new NegatedServerWebExchangeMatcher(
				ServerWebExchangeMatchers.pathMatchers("/favicon.*"));
		MediaTypeServerWebExchangeMatcher html = new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML);
		html.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		return new AndServerWebExchangeMatcher(get, notFavicon, html);
	}

}
