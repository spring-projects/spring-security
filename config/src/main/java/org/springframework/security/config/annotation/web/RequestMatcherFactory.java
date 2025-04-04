/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.config.annotation.web;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * This utility exists only to facilitate applications opting into using path patterns in
 * the HttpSecurity DSL. It is for internal use only.
 *
 * @deprecated
 */
@Deprecated(forRemoval = true)
public final class RequestMatcherFactory {

	private static PathPatternRequestMatcher.Builder builder;

	public static void setApplicationContext(ApplicationContext context) {
		builder = context.getBeanProvider(PathPatternRequestMatcher.Builder.class).getIfUnique();
	}

	public static boolean usesPathPatterns() {
		return builder != null;
	}

	public static RequestMatcher matcher(String path) {
		return matcher(null, path);
	}

	public static RequestMatcher matcher(HttpMethod method, String path) {
		if (builder != null) {
			return builder.matcher(method, path);
		}
		return new AntPathRequestMatcher(path, (method != null) ? method.name() : null);
	}

	private RequestMatcherFactory() {

	}

}
