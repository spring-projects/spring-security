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

package org.springframework.security.authorization.method;

import java.lang.reflect.Method;

import org.jspecify.annotations.Nullable;

import org.springframework.context.ApplicationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;

/**
 * For internal use only, as this contract is likely to change.
 *
 * @author Evgeniy Cheban
 * @author DingHao
 * @since 5.8
 */
final class PostAuthorizeExpressionAttributeRegistry extends AbstractExpressionAttributeRegistry<ExpressionAttribute> {

	private final MethodAuthorizationDeniedHandlerResolver handlerResolver = new MethodAuthorizationDeniedHandlerResolver(
			PostAuthorizeAuthorizationManager.class);

	private SecurityAnnotationScanner<PostAuthorize> postAuthorizeScanner = SecurityAnnotationScanners
		.requireUnique(PostAuthorize.class);

	@Override
	@Nullable ExpressionAttribute resolveAttribute(Method method, @Nullable Class<?> targetClass) {
		PostAuthorize postAuthorize = findPostAuthorizeAnnotation(method, targetClass);
		if (postAuthorize == null) {
			return null;
		}
		Expression expression = getExpressionHandler().getExpressionParser().parseExpression(postAuthorize.value());
		MethodAuthorizationDeniedHandler deniedHandler = this.handlerResolver.resolve(method,
				targetClass(method, targetClass));
		return new PostAuthorizeExpressionAttribute(expression, deniedHandler);
	}

	private @Nullable PostAuthorize findPostAuthorizeAnnotation(Method method, @Nullable Class<?> targetClass) {
		Class<?> targetClassToUse = targetClass(method, targetClass);
		return this.postAuthorizeScanner.scan(method, targetClassToUse);
	}

	/**
	 * Uses the provided {@link ApplicationContext} to resolve the
	 * {@link MethodAuthorizationDeniedHandler} from {@link PostAuthorize}
	 * @param context the {@link ApplicationContext} to use
	 */
	void setApplicationContext(ApplicationContext context) {
		this.handlerResolver.setContext(context);
	}

	void setTemplateDefaults(AnnotationTemplateExpressionDefaults templateDefaults) {
		this.postAuthorizeScanner = SecurityAnnotationScanners.requireUnique(PostAuthorize.class, templateDefaults);
	}

}
