/*
 * Copyright 2002-2016 the original author or authors.
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

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;

/**
 * Simple expression configuration attribute for use in web request authorizations.
 *
 * @author Luke Taylor
 * @since 3.0
 */
class WebExpressionConfigAttribute implements ConfigAttribute, EvaluationContextPostProcessor<FilterInvocation> {

	private final Expression authorizeExpression;

	private final EvaluationContextPostProcessor<FilterInvocation> postProcessor;

	WebExpressionConfigAttribute(Expression authorizeExpression,
			EvaluationContextPostProcessor<FilterInvocation> postProcessor) {
		this.authorizeExpression = authorizeExpression;
		this.postProcessor = postProcessor;
	}

	Expression getAuthorizeExpression() {
		return this.authorizeExpression;
	}

	@Override
	public EvaluationContext postProcess(EvaluationContext context, FilterInvocation fi) {
		return this.postProcessor == null ? context : this.postProcessor.postProcess(context, fi);
	}

	@Override
	public String getAttribute() {
		return null;
	}

	@Override
	public String toString() {
		return this.authorizeExpression.getExpressionString();
	}

}
