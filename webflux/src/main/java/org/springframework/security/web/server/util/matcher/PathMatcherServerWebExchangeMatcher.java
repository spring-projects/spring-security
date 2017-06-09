/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
package org.springframework.security.web.server.util.matcher;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.Assert;
import org.springframework.util.PathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.ParsingPathMatcher;
import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.0
 */
public final class PathMatcherServerWebExchangeMatcher implements ServerWebExchangeMatcher {
	private static final PathMatcher DEFAULT_PATH_MATCHER = new ParsingPathMatcher();

	private PathMatcher pathMatcher = DEFAULT_PATH_MATCHER;

	private final String pattern;
	private final HttpMethod method;

	public PathMatcherServerWebExchangeMatcher(String pattern) {
		this(pattern, null);
	}

	public PathMatcherServerWebExchangeMatcher(String pattern, HttpMethod method) {
		Assert.notNull(pattern, "pattern cannot be null");
		this.pattern = pattern;
		this.method = method;
	}

	@Override
	public Mono<MatchResult> matches(ServerWebExchange exchange) {
		ServerHttpRequest request = exchange.getRequest();
		if(this.method != null && !this.method.equals(request.getMethod())) {
			return MatchResult.notMatch();
		}
		String path = request.getPathWithinApplication();
		boolean match = pathMatcher.match(pattern, path);
		if(!match) {
			return MatchResult.notMatch();
		}
		Map<String,String> pathVariables = pathMatcher.extractUriTemplateVariables(pattern, path);
		Map<String,Object> variables = new HashMap<>(pathVariables);
		return MatchResult.match(variables);
	}

	public void setPathMatcher(PathMatcher pathMatcher) {
		Assert.notNull(pathMatcher, "pathMatcher cannot be null");
		this.pathMatcher = pathMatcher;
	}

	@Override
	public String toString() {
		return "PathMatcherServerWebExchangeMatcher{" +
				"pattern='" + pattern + '\'' +
				", method=" + method +
				'}';
	}
}
