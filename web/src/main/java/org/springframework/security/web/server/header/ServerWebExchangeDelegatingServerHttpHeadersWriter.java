/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.server.header;

import reactor.core.publisher.Mono;

import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Delegates to a provided {@link ServerHttpHeadersWriter} if
 * {@link ServerWebExchangeMatcher#matches(ServerWebExchange)} returns a match.
 *
 * @author David Herberth
 * @since 5.8
 */
public final class ServerWebExchangeDelegatingServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	private final ServerWebExchangeMatcherEntry<ServerHttpHeadersWriter> headersWriter;

	/**
	 * Creates a new instance
	 * @param headersWriter the {@link ServerWebExchangeMatcherEntry} holding a
	 * {@link ServerWebExchangeMatcher} and the {@link ServerHttpHeadersWriter} to invoke
	 * if the matcher returns a match.
	 */
	public ServerWebExchangeDelegatingServerHttpHeadersWriter(
			ServerWebExchangeMatcherEntry<ServerHttpHeadersWriter> headersWriter) {
		Assert.notNull(headersWriter, "headersWriter cannot be null");
		Assert.notNull(headersWriter.getMatcher(), "webExchangeMatcher cannot be null");
		Assert.notNull(headersWriter.getEntry(), "delegateHeadersWriter cannot be null");
		this.headersWriter = headersWriter;
	}

	/**
	 * Creates a new instance
	 * @param webExchangeMatcher the {@link ServerWebExchangeMatcher} to use. If it
	 * returns a match, the delegateHeadersWriter is invoked.
	 * @param delegateHeadersWriter the {@link ServerHttpHeadersWriter} to invoke if the
	 * {@link ServerWebExchangeMatcher} returns a match.
	 */
	public ServerWebExchangeDelegatingServerHttpHeadersWriter(ServerWebExchangeMatcher webExchangeMatcher,
			ServerHttpHeadersWriter delegateHeadersWriter) {
		this(new ServerWebExchangeMatcherEntry<>(webExchangeMatcher, delegateHeadersWriter));
	}

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return this.headersWriter.getMatcher().matches(exchange).filter(ServerWebExchangeMatcher.MatchResult::isMatch)
				.flatMap((matchResult) -> this.headersWriter.getEntry().writeHttpHeaders(exchange));
	}

}
