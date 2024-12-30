/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authorization.method;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authorization.AuthorizationResult;

final class ReflectiveMethodAuthorizationDeniedHandler implements MethodAuthorizationDeniedHandler {

	private final Log logger = LogFactory.getLog(getClass());

	private final Class<?> targetClass;

	private final Class<?> managerClass;

	ReflectiveMethodAuthorizationDeniedHandler(Class<?> targetClass, Class<?> managerClass) {
		this.logger.debug(
				"Will attempt to instantiate handlerClass attributes using reflection since no application context was supplied to "
						+ managerClass);
		this.targetClass = targetClass;
		this.managerClass = managerClass;
	}

	@Override
	public Object handleDeniedInvocation(MethodInvocation methodInvocation, AuthorizationResult authorizationResult) {
		return constructMethodAuthorizationDeniedHandler().handleDeniedInvocation(methodInvocation,
				authorizationResult);
	}

	@Override
	public Object handleDeniedInvocationResult(MethodInvocationResult methodInvocationResult,
			AuthorizationResult authorizationResult) {
		return constructMethodAuthorizationDeniedHandler().handleDeniedInvocationResult(methodInvocationResult,
				authorizationResult);
	}

	private MethodAuthorizationDeniedHandler constructMethodAuthorizationDeniedHandler() {
		try {
			return ((MethodAuthorizationDeniedHandler) this.targetClass.getConstructor().newInstance());
		}
		catch (Exception ex) {
			throw new IllegalArgumentException("Failed to construct instance of " + this.targetClass
					+ ". Please either add a public default constructor to the class "
					+ " or publish an instance of it as a Spring bean. If you publish it as a Spring bean, "
					+ " either add `@EnableMethodSecurity` to your configuration or "
					+ " provide the `ApplicationContext` directly to " + this.managerClass, ex);
		}
	}

}
