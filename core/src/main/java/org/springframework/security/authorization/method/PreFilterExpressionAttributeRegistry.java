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

import org.springframework.aop.support.AopUtils;
import org.springframework.expression.Expression;
import org.springframework.lang.NonNull;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.annotation.AnnotationSynthesizer;
import org.springframework.security.core.annotation.AnnotationSynthesizers;

/**
 * For internal use only, as this contract is likely to change.
 *
 * @author Evgeniy Cheban
 * @author DingHao
 * @since 5.8
 */
final class PreFilterExpressionAttributeRegistry
		extends AbstractExpressionAttributeRegistry<PreFilterExpressionAttributeRegistry.PreFilterExpressionAttribute> {

	private AnnotationSynthesizer<PreFilter> synthesizer = AnnotationSynthesizers.requireUnique(PreFilter.class);

	@NonNull
	@Override
	PreFilterExpressionAttribute resolveAttribute(Method method, Class<?> targetClass) {
		Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
		PreFilter preFilter = findPreFilterAnnotation(specificMethod, targetClass);
		if (preFilter == null) {
			return PreFilterExpressionAttribute.NULL_ATTRIBUTE;
		}
		Expression preFilterExpression = getExpressionHandler().getExpressionParser()
			.parseExpression(preFilter.value());
		return new PreFilterExpressionAttribute(preFilterExpression, preFilter.filterTarget());
	}

	void setTemplateDefaults(PrePostTemplateDefaults defaults) {
		this.synthesizer = AnnotationSynthesizers.requireUnique(PreFilter.class, defaults);
	}

	private PreFilter findPreFilterAnnotation(Method method, Class<?> targetClass) {
		Class<?> targetClassToUse = targetClass(method, targetClass);
		return this.synthesizer.synthesize(method, targetClassToUse);
	}

	static final class PreFilterExpressionAttribute extends ExpressionAttribute {

		static final PreFilterExpressionAttribute NULL_ATTRIBUTE = new PreFilterExpressionAttribute(null, null);

		private final String filterTarget;

		private PreFilterExpressionAttribute(Expression expression, String filterTarget) {
			super(expression);
			this.filterTarget = filterTarget;
		}

		String getFilterTarget() {
			return this.filterTarget;
		}

	}

}
