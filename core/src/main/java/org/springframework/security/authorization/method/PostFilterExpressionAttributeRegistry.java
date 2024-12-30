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

import org.springframework.expression.Expression;
import org.springframework.lang.NonNull;
import org.springframework.security.access.prepost.PostFilter;
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
final class PostFilterExpressionAttributeRegistry extends AbstractExpressionAttributeRegistry<ExpressionAttribute> {

	private SecurityAnnotationScanner<PostFilter> scanner = SecurityAnnotationScanners.requireUnique(PostFilter.class);

	@NonNull
	@Override
	ExpressionAttribute resolveAttribute(Method method, Class<?> targetClass) {
		PostFilter postFilter = findPostFilterAnnotation(method, targetClass);
		if (postFilter == null) {
			return ExpressionAttribute.NULL_ATTRIBUTE;
		}
		Expression postFilterExpression = getExpressionHandler().getExpressionParser()
			.parseExpression(postFilter.value());
		return new ExpressionAttribute(postFilterExpression);
	}

	void setTemplateDefaults(AnnotationTemplateExpressionDefaults defaults) {
		this.scanner = SecurityAnnotationScanners.requireUnique(PostFilter.class, defaults);
	}

	private PostFilter findPostFilterAnnotation(Method method, Class<?> targetClass) {
		Class<?> targetClassToUse = targetClass(method, targetClass);
		return this.scanner.scan(method, targetClassToUse);
	}

}
