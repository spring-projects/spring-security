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
package org.springframework.security.web.server.util.matcher;

import java.util.Arrays;
import java.util.List;

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Matches if any of the provided {@link ServerWebExchangeMatcher} match
 * @author Rob Winch
 * @since 5.0
 * @see AndServerWebExchangeMatcher
 */
public class OrServerWebExchangeMatcher implements ServerWebExchangeMatcher {
	private final List<ServerWebExchangeMatcher> matchers;

	public OrServerWebExchangeMatcher(List<ServerWebExchangeMatcher> matchers) {
		Assert.notEmpty(matchers, "matchers cannot be empty");
		this.matchers = matchers;
	}


	public OrServerWebExchangeMatcher(ServerWebExchangeMatcher... matchers) {
		this(Arrays.asList(matchers));
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher#matches(org.springframework.web.server.ServerWebExchange)
	 */
	@Override
	public Mono<MatchResult> matches(ServerWebExchange exchange) {
		return Flux.fromIterable(matchers)
			.flatMap(m -> m.matches(exchange))
			.filter(m -> m.isMatch())
			.next()
			.switchIfEmpty(MatchResult.notMatch());
	}

	@Override
	public String toString() {
		return "OrServerWebExchangeMatcher{" +
				"matchers=" + matchers +
				'}';
	}
}
