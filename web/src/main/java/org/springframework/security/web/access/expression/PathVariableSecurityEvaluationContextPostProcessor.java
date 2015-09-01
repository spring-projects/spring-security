/*
 * Copyright 2002-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.access.expression;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.expression.EvaluationContext;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

/**
 * Exposes URI template variables as variables on the {@link EvaluationContext}.
 * For example, the pattern "/user/{username}/**" would expose a variable named
 * username based on the current URI.
 *
 * <p>
 * NOTE: This API is intentionally kept package scope as it may change in the future. It may be nice to allow users to augment expressions and queries
 * </p>
 *
 * @author Rob Winch
 * @since 4.1
 */
class PathVariableSecurityEvaluationContextPostProcessor implements SecurityEvaluationContextPostProcessor<FilterInvocation> {
	private final PathMatcher matcher = new AntPathMatcher();
	private final String antPattern;

	/**
	 * Creates a new instance.
	 *
	 * @param antPattern the ant pattern that may have template variables (i.e. "/user/{username}/**)
	 */
	public PathVariableSecurityEvaluationContextPostProcessor(String antPattern) {
		this.antPattern = antPattern;
	}

	public EvaluationContext postProcess(EvaluationContext context, FilterInvocation invocation) {
		if(antPattern == null) {
			return context;
		}

		String path = getRequestPath(invocation.getHttpRequest());
		Map<String, String> variables = matcher.extractUriTemplateVariables(antPattern, path);
		for(Map.Entry<String, String> entry : variables.entrySet()) {
			context.setVariable(entry.getKey(), entry.getValue());
		}
		return context;
	}

	private String getRequestPath(HttpServletRequest request) {
		String url = request.getServletPath();

		if (request.getPathInfo() != null) {
			url += request.getPathInfo();
		}

		return url;
	}
}
