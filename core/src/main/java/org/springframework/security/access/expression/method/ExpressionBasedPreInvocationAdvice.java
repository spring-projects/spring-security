/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.access.expression.method;

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdvice;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Method pre-invocation handling based on expressions.
 *
 * @author Luke Taylor
 * @since 3.0
 * @deprecated Use
 * {@link org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor}
 * instead
 */
@Deprecated
public class ExpressionBasedPreInvocationAdvice implements PreInvocationAuthorizationAdvice {

	private MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

	@Override
	public boolean before(Authentication authentication, MethodInvocation mi, PreInvocationAttribute attr) {
		PreInvocationExpressionAttribute preAttr = (PreInvocationExpressionAttribute) attr;
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication, mi);
		Expression preFilter = preAttr.getFilterExpression();
		Expression preAuthorize = preAttr.getAuthorizeExpression();
		if (preFilter != null) {
			Object filterTarget = findFilterTarget(preAttr.getFilterTarget(), ctx, mi);
			this.expressionHandler.filter(filterTarget, preFilter, ctx);
		}
		return (preAuthorize != null) ? ExpressionUtils.evaluateAsBoolean(preAuthorize, ctx) : true;
	}

	private Object findFilterTarget(String filterTargetName, EvaluationContext ctx, MethodInvocation invocation) {
		Object filterTarget;

		if (filterTargetName.length() > 0) {
			filterTarget = ctx.lookupVariable(filterTargetName);
			Assert.notNull(filterTarget,
					() -> new StringBuilder("Filter target was null, or no argument with name ").append(filterTargetName).append(" found in method").toString());
			assertIsNotOfTypeArray(filterTarget);

			return filterTarget;
		}

		Object[] args = invocation.getArguments();

		if (args.length > 1) {
			throw new IllegalArgumentException(
					"Unable to determine the method argument for filtering. Specify the filter target.");
		}

		if (args.length == 1 && firstArgIsArrayOrCollection(args[0])) {
			filterTarget = args[0];
			Assert.notNull(filterTarget, () -> new StringBuilder("A PreFilter expression was set but the method argument type")
					.append(args[0].getClass()).append(" is not filterable").toString());
			assertIsNotOfTypeArray(filterTarget);
			return filterTarget;
		}

		throw new IllegalStateException("Unexpected either filterTargetName or invocation arguments provided. Provide either the target name or invocation argument with one argument");
	}

	private boolean firstArgIsArrayOrCollection(Object arg) {
		return arg.getClass().isArray() || arg instanceof Collection<?>;
	}

	private void assertIsNotOfTypeArray(Object filterTarget) {
		Assert.isTrue(!filterTarget.getClass().isArray(),
				"Pre-filtering on array types is not supported. Using a Collection will solve this problem");
	}

	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		this.expressionHandler = expressionHandler;
	}

}
