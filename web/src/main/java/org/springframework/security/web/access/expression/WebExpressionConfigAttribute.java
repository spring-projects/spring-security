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
class WebExpressionConfigAttribute implements ConfigAttribute, SecurityEvaluationContextPostProcessor<FilterInvocation> {
	private final Expression authorizeExpression;
	private final SecurityEvaluationContextPostProcessor<FilterInvocation> postProcessor;

	public WebExpressionConfigAttribute(Expression authorizeExpression, SecurityEvaluationContextPostProcessor<FilterInvocation> postProcessor) {
		this.authorizeExpression = authorizeExpression;
		this.postProcessor = postProcessor;
	}

	Expression getAuthorizeExpression() {
		return authorizeExpression;
	}

	public EvaluationContext postProcess(EvaluationContext context, FilterInvocation fi) {
		return postProcessor.postProcess(context, fi);
	}

	public String getAttribute() {
		return null;
	}

	@Override
	public String toString() {
		return authorizeExpression.getExpressionString();
	}
}
