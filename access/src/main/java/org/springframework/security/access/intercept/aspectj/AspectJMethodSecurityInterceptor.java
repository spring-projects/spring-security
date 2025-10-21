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

package org.springframework.security.access.intercept.aspectj;

import org.aspectj.lang.JoinPoint;

import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;

/**
 * AspectJ {@code JoinPoint} security interceptor which wraps the {@code JoinPoint} in a
 * {@code MethodInvocation} adapter to make it compatible with security infrastructure
 * classes which only support {@code MethodInvocation}s.
 * <p>
 * One of the {@code invoke} methods should be called from the {@code around()} advice in
 * your aspect. Alternatively you can use one of the pre-defined aspects from the aspects
 * module.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0.3
 * @deprecated This class will be removed from the public API. Please either use
 * `spring-security-aspects`, Spring Security's method security support or create your own
 * class that uses Spring AOP annotations.
 */
@Deprecated
public final class AspectJMethodSecurityInterceptor extends MethodSecurityInterceptor {

	/**
	 * Method that is suitable for user with @Aspect notation.
	 * @param jp The AspectJ joint point being invoked which requires a security decision
	 * @return The returned value from the method invocation
	 * @throws Throwable if the invocation throws one
	 */
	public Object invoke(JoinPoint jp) throws Throwable {
		return super.invoke(new MethodInvocationAdapter(jp));
	}

	/**
	 * Method that is suitable for user with traditional AspectJ-code aspects.
	 * @param jp The AspectJ joint point being invoked which requires a security decision
	 * @param advisorProceed the advice-defined anonymous class that implements
	 * {@code AspectJCallback} containing a simple {@code return proceed();} statement
	 * @return The returned value from the method invocation
	 */
	public Object invoke(JoinPoint jp, AspectJCallback advisorProceed) {
		InterceptorStatusToken token = super.beforeInvocation(new MethodInvocationAdapter(jp));
		Object result;
		try {
			result = advisorProceed.proceedWithObject();
		}
		finally {
			super.finallyInvocation(token);
		}
		return super.afterInvocation(token, result);
	}

}
