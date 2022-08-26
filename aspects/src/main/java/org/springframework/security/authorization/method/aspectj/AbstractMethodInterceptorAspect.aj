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
package org.springframework.security.authorization.method.aspectj;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.prepost.PostAuthorize;

/**
 * Abstract AspectJ aspect for adapting a {@link MethodInvocation}
 *
 * @author Josh Cummings
 * @since 5.8
 */
abstract aspect AbstractMethodInterceptorAspect {

	protected abstract pointcut executionOfAnnotatedMethod();

	private MethodInterceptor securityInterceptor;

	Object around(): executionOfAnnotatedMethod() {
		if (this.securityInterceptor == null) {
			return proceed();
		}
		MethodInvocation invocation = new JoinPointMethodInvocation(thisJoinPoint, () -> proceed());
		try {
			return this.securityInterceptor.invoke(invocation);
		} catch (Throwable t) {
			throwUnchecked(t);
			throw new IllegalStateException("Code unexpectedly reached", t);
		}
	}

	public void setSecurityInterceptor(MethodInterceptor securityInterceptor) {
		this.securityInterceptor = securityInterceptor;
	}

	private static void throwUnchecked(Throwable ex) {
		AbstractMethodInterceptorAspect.<RuntimeException>throwAny(ex);
	}

	@SuppressWarnings("unchecked")
	private static <E extends Throwable> void throwAny(Throwable ex) throws E {
		throw (E) ex;
	}
}
