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
package org.springframework.security.web.server.util.matcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Negates the provided matcher. If the provided matcher returns true, then the result will be false. If the provided
 * matcher returns false, then the result will be true.
 * @author Tao Qian
 * @author Mathieu Ouellet
 * @since 5.1
 */
public class NegatedServerWebExchangeMatcher implements ServerWebExchangeMatcher {
	private static final Log logger = LogFactory.getLog(NegatedServerWebExchangeMatcher.class);
	private final ServerWebExchangeMatcher matcher;

	public NegatedServerWebExchangeMatcher(ServerWebExchangeMatcher matcher) {
		Assert.notNull(matcher, "matcher cannot be null");
		this.matcher = matcher;
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher#matches(org.springframework.web.server.ServerWebExchange)
	 */
	@Override
	public Mono<MatchResult> matches(ServerWebExchange exchange) {
		return matcher.matches(exchange)
			.flatMap(m -> m.isMatch() ? MatchResult.notMatch() : MatchResult.match())
			.doOnNext(it -> {
				if (logger.isDebugEnabled()) {
					logger.debug("matches = " + it.isMatch());
				}
			});
	}

	@Override
	public String toString() {
		return "NegatedServerWebExchangeMatcher{" +
				"matcher=" + matcher +
				'}';
	}
}
