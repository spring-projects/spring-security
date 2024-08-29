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

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.function.Function;

import reactor.util.annotation.NonNull;

import org.springframework.context.ApplicationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;
import org.springframework.util.Assert;

/**
 * For internal use only, as this contract is likely to change.
 *
 * @author Evgeniy Cheban
 * @author DingHao
 * @since 5.8
 */
final class PreAuthorizeExpressionAttributeRegistry extends AbstractExpressionAttributeRegistry<ExpressionAttribute> {

	private final MethodAuthorizationDeniedHandler defaultHandler = new ThrowingMethodAuthorizationDeniedHandler();

	private final SecurityAnnotationScanner<HandleAuthorizationDenied> handleAuthorizationDeniedScanner = SecurityAnnotationScanners
		.requireUnique(HandleAuthorizationDenied.class);

	private Function<Class<? extends MethodAuthorizationDeniedHandler>, MethodAuthorizationDeniedHandler> handlerResolver;

	private SecurityAnnotationScanner<PreAuthorize> preAuthorizeScanner = SecurityAnnotationScanners
		.requireUnique(PreAuthorize.class);

	PreAuthorizeExpressionAttributeRegistry() {
		this.handlerResolver = (clazz) -> new ReflectiveMethodAuthorizationDeniedHandler(clazz,
				PreAuthorizeAuthorizationManager.class);
	}

	@NonNull
	@Override
	ExpressionAttribute resolveAttribute(Method method, Class<?> targetClass) {
		PreAuthorize preAuthorize = findPreAuthorizeAnnotation(method, targetClass);
		if (preAuthorize == null) {
			return ExpressionAttribute.NULL_ATTRIBUTE;
		}
		Expression expression = getExpressionHandler().getExpressionParser().parseExpression(preAuthorize.value());
		MethodAuthorizationDeniedHandler handler = resolveHandler(method, targetClass);
		return new PreAuthorizeExpressionAttribute(expression, handler);
	}

	private MethodAuthorizationDeniedHandler resolveHandler(Method method, Class<?> targetClass) {
		Class<?> targetClassToUse = targetClass(method, targetClass);
		HandleAuthorizationDenied deniedHandler = this.handleAuthorizationDeniedScanner.scan(method, targetClassToUse);
		if (deniedHandler != null) {
			return this.handlerResolver.apply(deniedHandler.handlerClass());
		}
		return this.defaultHandler;
	}

	private PreAuthorize findPreAuthorizeAnnotation(Method method, Class<?> targetClass) {
		Class<?> targetClassToUse = targetClass(method, targetClass);
		return this.preAuthorizeScanner.scan(method, targetClassToUse);
	}

	/**
	 * Uses the provided {@link ApplicationContext} to resolve the
	 * {@link MethodAuthorizationDeniedHandler} from {@link PreAuthorize}.
	 * @param context the {@link ApplicationContext} to use
	 */
	void setApplicationContext(ApplicationContext context) {
		Assert.notNull(context, "context cannot be null");
		this.handlerResolver = (clazz) -> resolveHandler(context, clazz);
	}

	void setTemplateDefaults(AnnotationTemplateExpressionDefaults defaults) {
		this.preAuthorizeScanner = SecurityAnnotationScanners.requireUnique(PreAuthorize.class, defaults);
	}

	private MethodAuthorizationDeniedHandler resolveHandler(ApplicationContext context,
			Class<? extends MethodAuthorizationDeniedHandler> handlerClass) {
		if (handlerClass == this.defaultHandler.getClass()) {
			return this.defaultHandler;
		}
		String[] beanNames = context.getBeanNamesForType(handlerClass);
		if (beanNames.length == 0) {
			throw new IllegalStateException("Could not find a bean of type " + handlerClass.getName());
		}
		if (beanNames.length > 1) {
			throw new IllegalStateException("Expected to find a single bean of type " + handlerClass.getName()
					+ " but found " + Arrays.toString(beanNames));
		}
		return context.getBean(beanNames[0], handlerClass);
	}

}
