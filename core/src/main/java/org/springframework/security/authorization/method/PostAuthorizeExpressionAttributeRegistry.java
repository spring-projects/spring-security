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

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.function.Function;

import reactor.util.annotation.NonNull;

import org.springframework.aop.support.AopUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.util.Assert;

/**
 * For internal use only, as this contract is likely to change.
 *
 * @author Evgeniy Cheban
 * @author DingHao
 * @since 5.8
 */
final class PostAuthorizeExpressionAttributeRegistry extends AbstractExpressionAttributeRegistry<ExpressionAttribute> {

	private final MethodAuthorizationDeniedPostProcessor defaultPostProcessor = new ThrowingMethodAuthorizationDeniedPostProcessor();

	private Function<Class<? extends MethodAuthorizationDeniedPostProcessor>, MethodAuthorizationDeniedPostProcessor> postProcessorResolver;

	PostAuthorizeExpressionAttributeRegistry() {
		this.postProcessorResolver = (clazz) -> this.defaultPostProcessor;
	}

	@NonNull
	@Override
	ExpressionAttribute resolveAttribute(Method method, Class<?> targetClass) {
		Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
		PostAuthorize postAuthorize = findPostAuthorizeAnnotation(specificMethod, targetClass);
		if (postAuthorize == null) {
			return ExpressionAttribute.NULL_ATTRIBUTE;
		}
		Expression expression = getExpressionHandler().getExpressionParser().parseExpression(postAuthorize.value());
		MethodAuthorizationDeniedPostProcessor postProcessor = resolvePostProcessor(method, targetClass);
		return new PostAuthorizeExpressionAttribute(expression, postProcessor);
	}

	private MethodAuthorizationDeniedPostProcessor resolvePostProcessor(Method method, Class<?> targetClass) {
		Function<AnnotatedElement, AuthorizationDeniedHandler> lookup = AuthorizationAnnotationUtils
			.withDefaults(AuthorizationDeniedHandler.class);
		AuthorizationDeniedHandler deniedHandler = lookup.apply(method);
		if (deniedHandler != null) {
			return this.postProcessorResolver.apply(deniedHandler.postProcessorClass());
		}
		deniedHandler = lookup.apply(targetClass(method, targetClass));
		if (deniedHandler != null) {
			return this.postProcessorResolver.apply(deniedHandler.postProcessorClass());
		}
		return this.defaultPostProcessor;
	}

	private PostAuthorize findPostAuthorizeAnnotation(Method method, Class<?> targetClass) {
		Function<AnnotatedElement, PostAuthorize> lookup = findUniqueAnnotation(PostAuthorize.class);
		PostAuthorize postAuthorize = lookup.apply(method);
		return (postAuthorize != null) ? postAuthorize : lookup.apply(targetClass(method, targetClass));
	}

	/**
	 * Uses the provided {@link ApplicationContext} to resolve the
	 * {@link MethodAuthorizationDeniedPostProcessor} from {@link PostAuthorize}
	 * @param context the {@link ApplicationContext} to use
	 */
	void setApplicationContext(ApplicationContext context) {
		Assert.notNull(context, "context cannot be null");
		this.postProcessorResolver = (postProcessorClass) -> resolvePostProcessor(context, postProcessorClass);
	}

	private MethodAuthorizationDeniedPostProcessor resolvePostProcessor(ApplicationContext context,
			Class<? extends MethodAuthorizationDeniedPostProcessor> postProcessorClass) {
		if (postProcessorClass == this.defaultPostProcessor.getClass()) {
			return this.defaultPostProcessor;
		}
		String[] beanNames = context.getBeanNamesForType(postProcessorClass);
		if (beanNames.length == 0) {
			throw new IllegalStateException("Could not find a bean of type " + postProcessorClass.getName());
		}
		if (beanNames.length > 1) {
			throw new IllegalStateException("Expected to find a single bean of type " + postProcessorClass.getName()
					+ " but found " + Arrays.toString(beanNames));
		}
		return context.getBean(beanNames[0], postProcessorClass);
	}

}
