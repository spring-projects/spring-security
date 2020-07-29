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

import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * A {@link ServerAuthenticationEntryPoint} which delegates to multiple
 * {@link ServerAuthenticationEntryPoint} based on a {@link ServerWebExchangeMatcher}
 *
 * @author Rob Winch
 * @author Mathieu Ouellet
 * @since 5.0
 */
public class DelegatingServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

	private static final Log logger = LogFactory.getLog(DelegatingServerAuthenticationEntryPoint.class);

	private final List<DelegateEntry> entryPoints;

	private ServerAuthenticationEntryPoint defaultEntryPoint = (exchange, e) -> {
		exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
		return exchange.getResponse().setComplete();
	};

	public DelegatingServerAuthenticationEntryPoint(DelegateEntry... entryPoints) {
		this(Arrays.asList(entryPoints));
	}

	public DelegatingServerAuthenticationEntryPoint(List<DelegateEntry> entryPoints) {
		Assert.notEmpty(entryPoints, "entryPoints cannot be null");
		this.entryPoints = entryPoints;
	}

	@Override
	public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
		return Flux.fromIterable(this.entryPoints).filterWhen(entry -> isMatch(exchange, entry)).next()
				.map(entry -> entry.getEntryPoint()).doOnNext(it -> {
					if (logger.isDebugEnabled()) {
						logger.debug("Match found! Executing " + it);
					}
				}).switchIfEmpty(Mono.just(this.defaultEntryPoint).doOnNext(it -> {
					if (logger.isDebugEnabled()) {
						logger.debug("No match found. Using default entry point " + this.defaultEntryPoint);
					}
				})).flatMap(entryPoint -> entryPoint.commence(exchange, ex));
	}

	private Mono<Boolean> isMatch(ServerWebExchange exchange, DelegateEntry entry) {
		ServerWebExchangeMatcher matcher = entry.getMatcher();
		if (logger.isDebugEnabled()) {
			logger.debug("Trying to match using " + matcher);
		}
		return matcher.matches(exchange).map(result -> result.isMatch());
	}

	/**
	 * EntryPoint which is used when no RequestMatcher returned true
	 */
	public void setDefaultEntryPoint(ServerAuthenticationEntryPoint defaultEntryPoint) {
		this.defaultEntryPoint = defaultEntryPoint;
	}

	public static class DelegateEntry {

		private final ServerWebExchangeMatcher matcher;

		private final ServerAuthenticationEntryPoint entryPoint;

		public DelegateEntry(ServerWebExchangeMatcher matcher, ServerAuthenticationEntryPoint entryPoint) {
			this.matcher = matcher;
			this.entryPoint = entryPoint;
		}

		public ServerWebExchangeMatcher getMatcher() {
			return this.matcher;
		}

		public ServerAuthenticationEntryPoint getEntryPoint() {
			return this.entryPoint;
		}

	}

}
