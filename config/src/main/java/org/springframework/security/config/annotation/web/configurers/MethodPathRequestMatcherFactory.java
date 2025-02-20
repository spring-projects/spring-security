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

package org.springframework.security.config.annotation.web.configurers;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

interface MethodPathRequestMatcherFactory {

	default RequestMatcher matcher(String path) {
		return matcher(null, path);
	}

	RequestMatcher matcher(HttpMethod method, String path);

	static MethodPathRequestMatcherFactory fromApplicationContext(ApplicationContext context) {
		PathPatternRequestMatcher.Builder builder = context.getBeanProvider(PathPatternRequestMatcher.Builder.class)
			.getIfUnique();
		return (builder != null) ? builder::matcher : AntPathRequestMatcher::antMatcher;
	}

}
