/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

final class AntPathRequestMatcherBuilder implements RequestMatcherBuilder {

	private final String servletPath;

	private AntPathRequestMatcherBuilder(String servletPath) {
		this.servletPath = servletPath;
	}

	static AntPathRequestMatcherBuilder absolute() {
		return new AntPathRequestMatcherBuilder(null);
	}

	static AntPathRequestMatcherBuilder relativeTo(String path) {
		return new AntPathRequestMatcherBuilder(path);
	}

	@Override
	public AntPathRequestMatcher matcher(String pattern) {
		return matcher((String) null, pattern);
	}

	@Override
	public AntPathRequestMatcher matcher(HttpMethod method, String pattern) {
		return matcher((method != null) ? method.name() : null, pattern);
	}

	private AntPathRequestMatcher matcher(String method, String pattern) {
		return new AntPathRequestMatcher(prependServletPath(pattern), method);
	}

	private String prependServletPath(String pattern) {
		if (this.servletPath == null) {
			return pattern;
		}
		return this.servletPath + pattern;
	}

}
