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
import java.util.function.Function;

import reactor.util.annotation.NonNull;

import org.springframework.aop.support.AopUtils;
import org.springframework.expression.Expression;
import org.springframework.security.access.prepost.PostAuthorize;

/**
 * For internal use only, as this contract is likely to change.
 *
 * @author Evgeniy Cheban
 * @author DingHao
 * @since 5.8
 */
final class PostAuthorizeExpressionAttributeRegistry extends AbstractExpressionAttributeRegistry<ExpressionAttribute> {

	@NonNull
	@Override
	ExpressionAttribute resolveAttribute(Method method, Class<?> targetClass) {
		Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
		PostAuthorize postAuthorize = findPostAuthorizeAnnotation(specificMethod, targetClass);
		if (postAuthorize == null) {
			return ExpressionAttribute.NULL_ATTRIBUTE;
		}
		Expression expression = getExpressionHandler().getExpressionParser().parseExpression(postAuthorize.value());
		return new ExpressionAttribute(expression);
	}

	private PostAuthorize findPostAuthorizeAnnotation(Method method, Class<?> targetClass) {
		Function<AnnotatedElement, PostAuthorize> lookup = findUniqueAnnotation(PostAuthorize.class);
		PostAuthorize postAuthorize = lookup.apply(method);
		return (postAuthorize != null) ? postAuthorize : lookup.apply(targetClass(method, targetClass));
	}

}
