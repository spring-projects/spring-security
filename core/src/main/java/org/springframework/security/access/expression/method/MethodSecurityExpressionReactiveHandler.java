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
package org.springframework.security.access.expression.method;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.SecurityExpressionReactiveHandler;

/**
 * Extended expression-handler facade which adds methods which are specific to securing
 * method invocations.
 *
 * @author Luke Taylor
 * @author Sheiy
 * @since 5.4
 */
public interface MethodSecurityExpressionReactiveHandler extends
		SecurityExpressionReactiveHandler<MethodInvocation> {
	/**
	 * Filters a target collection or array. Only applies to method invocations.
	 *
	 * @param filterTarget the array or collection to be filtered.
	 * @param filterExpression the expression which should be used as the filter
	 * condition. If it returns false on evaluation, the object will be removed from the
	 * returned collection
	 * @param ctx the current evaluation context (as created through a call to
	 * {@link #createEvaluationContext(reactor.core.publisher.Mono, Object)}
	 * @return the filtered collection or array
	 */
	Object filter(Object filterTarget, Expression filterExpression, EvaluationContext ctx);

	/**
	 * Used to inform the expression system of the return object for the given evaluation
	 * context. Only applies to method invocations.
	 *
	 * @param returnObject the return object value
	 * @param ctx the context within which the object should be set (as created through a
	 * call to
	 * {@link #createEvaluationContext(reactor.core.publisher.Mono, Object)}
	 */
	void setReturnObject(Object returnObject, EvaluationContext ctx);

}
