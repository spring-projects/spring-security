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

package org.springframework.security.authorization.method;

import java.lang.reflect.Method;

import reactor.util.annotation.NonNull;

import org.springframework.aop.support.AopUtils;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.util.Assert;

/**
 * For internal use only, as this contract is likely to change.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
final class PostAuthorizeExpressionAttributeRegistry extends AbstractExpressionAttributeRegistry<ExpressionAttribute> {

	private final MethodSecurityExpressionHandler expressionHandler;

	PostAuthorizeExpressionAttributeRegistry() {
		this(new DefaultMethodSecurityExpressionHandler());
	}

	PostAuthorizeExpressionAttributeRegistry(MethodSecurityExpressionHandler expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
	}

	MethodSecurityExpressionHandler getExpressionHandler() {
		return this.expressionHandler;
	}

	@NonNull
	@Override
	ExpressionAttribute resolveAttribute(Method method, Class<?> targetClass) {
		Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
		PostAuthorize postAuthorize = findPostAuthorizeAnnotation(specificMethod);
		if (postAuthorize == null) {
			return ExpressionAttribute.NULL_ATTRIBUTE;
		}
		Expression postAuthorizeExpression = this.expressionHandler.getExpressionParser()
				.parseExpression(postAuthorize.value());
		return new ExpressionAttribute(postAuthorizeExpression);
	}

	private PostAuthorize findPostAuthorizeAnnotation(Method method) {
		PostAuthorize postAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(method, PostAuthorize.class);
		return (postAuthorize != null) ? postAuthorize
				: AuthorizationAnnotationUtils.findUniqueAnnotation(method.getDeclaringClass(), PostAuthorize.class);
	}

}
