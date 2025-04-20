/*
 * Copyright 2002-2025 the original author or authors.
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

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.function.BiFunction;

import org.springframework.context.ApplicationContext;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * For internal use only, as this contract is likely to change.
 *
 * @author Evgeniy Cheban
 */
final class MethodAuthorizationDeniedHandlerResolver {

	private final MethodAuthorizationDeniedHandler defaultHandler = new ThrowingMethodAuthorizationDeniedHandler();

	private final SecurityAnnotationScanner<HandleAuthorizationDenied> handleAuthorizationDeniedScanner = SecurityAnnotationScanners
		.requireUnique(HandleAuthorizationDenied.class);

	private BiFunction<String, Class<? extends MethodAuthorizationDeniedHandler>, MethodAuthorizationDeniedHandler> resolver;

	MethodAuthorizationDeniedHandlerResolver(Class<?> managerClass) {
		this.resolver = (beanName, handlerClass) -> new ReflectiveMethodAuthorizationDeniedHandler(handlerClass,
				managerClass);
	}

	void setContext(ApplicationContext context) {
		Assert.notNull(context, "context cannot be null");
		this.resolver = (beanName, handlerClass) -> doResolve(context, beanName, handlerClass);
	}

	MethodAuthorizationDeniedHandler resolve(Method method, Class<?> targetClass) {
		HandleAuthorizationDenied deniedHandler = this.handleAuthorizationDeniedScanner.scan(method, targetClass);
		if (deniedHandler != null) {
			return this.resolver.apply(deniedHandler.handler(), deniedHandler.handlerClass());
		}
		return this.defaultHandler;
	}

	private MethodAuthorizationDeniedHandler doResolve(ApplicationContext context, String beanName,
			Class<? extends MethodAuthorizationDeniedHandler> handlerClass) {
		if (StringUtils.hasText(beanName)) {
			return context.getBean(beanName, MethodAuthorizationDeniedHandler.class);
		}
		if (handlerClass == this.defaultHandler.getClass()) {
			return this.defaultHandler;
		}
		String[] beanNames = context.getBeanNamesForType(handlerClass);
		if (beanNames.length == 0) {
			throw new IllegalStateException("Could not find a bean of type " + handlerClass.getName());
		}
		if (beanNames.length > 1) {
			throw new IllegalStateException("Expected to find a single bean of type " + handlerClass.getName()
					+ " but found " + Arrays.toString(beanNames)
					+ " consider using 'handler' attribute to refer to specific bean");
		}
		return context.getBean(beanNames[0], handlerClass);
	}

}
