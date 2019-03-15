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

import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

/**
 * Matches if the {@link PathPattern} matches the path within the application.
 * @author Rob Winch
 * @since 5.0
 */
public final class PathPatternParserServerWebExchangeMatcher implements ServerWebExchangeMatcher {
	private static final PathPatternParser DEFAULT_PATTERN_PARSER = new PathPatternParser();

	private final PathPattern pattern;
	private final HttpMethod method;

	public PathPatternParserServerWebExchangeMatcher(PathPattern pattern) {
		this(pattern, null);
	}

	public PathPatternParserServerWebExchangeMatcher(PathPattern pattern, HttpMethod method) {
		Assert.notNull(pattern, "pattern cannot be null");
		this.pattern = pattern;
		this.method = method;
	}

	public PathPatternParserServerWebExchangeMatcher(String pattern, HttpMethod method) {
		Assert.notNull(pattern, "pattern cannot be null");
		this.pattern = DEFAULT_PATTERN_PARSER.parse(pattern);
		this.method = method;
	}

	public PathPatternParserServerWebExchangeMatcher(String pattern) {
		this(pattern, null);
	}

	@Override
	public Mono<MatchResult> matches(ServerWebExchange exchange) {
		ServerHttpRequest request = exchange.getRequest();
		if(this.method != null && !this.method.equals(request.getMethod())) {
			return MatchResult.notMatch();
		}
		PathContainer path = request.getPath().pathWithinApplication();
		boolean match = this.pattern.matches(path);
		if(!match) {
			return MatchResult.notMatch();
		}
		Map<String, String> pathVariables = this.pattern.matchAndExtract(path).getUriVariables();
		Map<String, Object> variables = new HashMap<>(pathVariables);
		return MatchResult.match(variables);
	}

	@Override
	public String toString() {
		return "PathMatcherServerWebExchangeMatcher{" +
				"pattern='" + pattern + '\'' +
				", method=" + method +
				'}';
	}
}
