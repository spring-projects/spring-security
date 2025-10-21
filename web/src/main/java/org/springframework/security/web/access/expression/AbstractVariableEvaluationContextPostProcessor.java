/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.access.expression;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;

import org.springframework.expression.EvaluationContext;
import org.springframework.security.web.FilterInvocation;

/**
 * Exposes URI template variables as variables on the {@link EvaluationContext}. For
 * example, the pattern "/user/{username}/**" would expose a variable named username based
 * on the current URI.
 *
 * <p>
 * NOTE: This API is intentionally kept package scope as it may change in the future. It
 * may be nice to allow users to augment expressions and queries
 * </p>
 *
 * @author Rob Winch
 * @since 4.1
 */
abstract class AbstractVariableEvaluationContextPostProcessor
		implements EvaluationContextPostProcessor<FilterInvocation> {

	@Override
	public final EvaluationContext postProcess(EvaluationContext context, FilterInvocation invocation) {
		return new VariableEvaluationContext(context, invocation.getHttpRequest());
	}

	abstract Map<String, String> extractVariables(HttpServletRequest request);

	/**
	 * {@link DelegatingEvaluationContext} to expose variable.
	 */
	class VariableEvaluationContext extends DelegatingEvaluationContext {

		private final HttpServletRequest request;

		private @Nullable Map<String, String> variables;

		VariableEvaluationContext(EvaluationContext delegate, HttpServletRequest request) {
			super(delegate);
			this.request = request;
		}

		@Override
		public @Nullable Object lookupVariable(String name) {
			Object result = super.lookupVariable(name);
			if (result != null) {
				return result;
			}
			if (this.variables == null) {
				this.variables = extractVariables(this.request);
			}
			return this.variables.get(name);
		}

	}

}
