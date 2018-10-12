/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.access.expression.method;

import org.aopalliance.intercept.MethodInvocation;
import org.reactivestreams.Publisher;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.lang.Nullable;
import org.springframework.security.access.expression.SecurityExpressionHandler;

/**
 * Extended expression-handler facade which adds methods which are specific to securing
 * method invocations on reactive types.
 * <p>
 *   Reactive equivalent of {@link MethodSecurityExpressionHandler}
 * </p>
 *
 * @author Eric Deandrea
 * @since 5.1.2
 * @see  MethodSecurityExpressionHandler
 */
public interface ReactiveMethodSecurityExpressionHandler extends SecurityExpressionHandler<MethodInvocation> {
	/**
	 * Filters a target {@link Publisher}. Only applies to method invocations.
	 *
	 * @param filterTarget The {@link Publisher} to be filtered. Really only makes sense for a {@link reactor.core.publisher.Flux Flux}.
	 * @param filterExpression The expression which should be used as the filter condition.
	 *                         If it returns false on evaluation, the object will be filtered out from
	 *                         the returned {@link Publisher}.
	 * @param ctx The current evaluation context (as created through a call to
	 *            {@link #createEvaluationContext(org.springframework.security.core.Authentication, Object)}
	 * @param <T> The type of {@link Publisher}
	 * @return The filtered {@link Publisher} if the {@link Publisher} is a {@link reactor.core.publisher.Flux}. Otherwise just returns the {@link Publisher}.
	 */
	<T extends Publisher<?>> T filter(T filterTarget, @Nullable Expression filterExpression, EvaluationContext ctx);

	/**
	 * Used to inform the expression system of the return object for the given evaluation
	 * context. Only applies to method invocations.
	 *
	 * @param returnObject The return object value
	 * @param ctx The context within which the object should be set (as created through a
	 *            call to {@link #createEvaluationContext(org.springframework.security.core.Authentication, Object)}
	 */
	void setReturnObject(Object returnObject, EvaluationContext ctx);
}
