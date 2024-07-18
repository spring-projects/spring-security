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

package org.springframework.security.core.annotation;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.HashMap;
import java.util.Map;

import org.springframework.core.MethodClassKey;
import org.springframework.core.annotation.MergedAnnotation;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.util.Assert;
import org.springframework.util.PropertyPlaceholderHelper;

/**
 * A strategy for synthesizing an annotation from an {@link AnnotatedElement} that
 * supports meta-annotations with placeholders, like the following:
 *
 * <pre>
 *	&#64;PreAuthorize("hasRole({role})")
 *	public @annotation HasRole {
 *		String role();
 *	}
 * </pre>
 *
 * <p>
 * In that case, you could use an {@link ExpressionTemplateAnnotationSynthesizer} of type
 * {@link org.springframework.security.access.prepost.PreAuthorize} to synthesize any
 * {@code @HasRole} annotation found on a given {@link AnnotatedElement}.
 *
 * <p>
 * Note that in all cases, Spring Security does not allow for repeatable annotations. So
 * this class delegates to {@link UniqueMergedAnnotationSynthesizer} in order to error if
 * a repeat is discovered.
 *
 * <p>
 * Since the process of synthesis is expensive, it is recommended to cache the synthesized
 * result to prevent multiple computations.
 *
 * @param <A> the annotation type
 * @author Josh Cummings
 * @since 6.4
 */
final class ExpressionTemplateAnnotationSynthesizer<A extends Annotation> implements AnnotationSynthesizer<A> {

	private final Class<A> type;

	private final UniqueMergedAnnotationSynthesizer<A> unique;

	private final AnnotationTemplateExpressionDefaults templateDefaults;

	private final Map<Parameter, MergedAnnotation<A>> uniqueParameterAnnotationCache = new HashMap<>();

	private final Map<MethodClassKey, MergedAnnotation<A>> uniqueMethodAnnotationCache = new HashMap<>();

	ExpressionTemplateAnnotationSynthesizer(Class<A> type, AnnotationTemplateExpressionDefaults templateDefaults) {
		Assert.notNull(type, "type cannot be null");
		Assert.notNull(templateDefaults, "templateDefaults cannot be null");
		this.type = type;
		this.unique = new UniqueMergedAnnotationSynthesizer<>(type);
		this.templateDefaults = templateDefaults;
	}

	@Override
	public MergedAnnotation<A> merge(AnnotatedElement element, Class<?> targetClass) {
		if (element instanceof Parameter parameter) {
			MergedAnnotation<A> annotation = this.uniqueParameterAnnotationCache.computeIfAbsent(parameter,
					(p) -> this.unique.merge(p, targetClass));
			if (annotation == null) {
				return null;
			}
			return resolvePlaceholders(annotation);
		}
		if (element instanceof Method method) {
			MethodClassKey key = new MethodClassKey(method, targetClass);
			MergedAnnotation<A> annotation = this.uniqueMethodAnnotationCache.computeIfAbsent(key,
					(k) -> this.unique.merge(method, targetClass));
			if (annotation == null) {
				return null;
			}
			return resolvePlaceholders(annotation);
		}
		throw new IllegalArgumentException("Unsupported element of type " + element.getClass());
	}

	private MergedAnnotation<A> resolvePlaceholders(MergedAnnotation<A> mergedAnnotation) {
		if (this.templateDefaults == null) {
			return mergedAnnotation;
		}
		if (mergedAnnotation.getMetaSource() == null) {
			return mergedAnnotation;
		}
		PropertyPlaceholderHelper helper = new PropertyPlaceholderHelper("{", "}", null, null,
				this.templateDefaults.isIgnoreUnknown());
		Map<String, Object> properties = new HashMap<>(mergedAnnotation.asMap());
		Map<String, Object> metaAnnotationProperties = mergedAnnotation.getMetaSource().asMap();
		Map<String, String> stringProperties = new HashMap<>();
		for (Map.Entry<String, Object> property : metaAnnotationProperties.entrySet()) {
			String key = property.getKey();
			Object value = property.getValue();
			String asString = (value instanceof String) ? (String) value
					: DefaultConversionService.getSharedInstance().convert(value, String.class);
			stringProperties.put(key, asString);
		}
		Map<String, Object> annotationProperties = mergedAnnotation.asMap();
		for (Map.Entry<String, Object> annotationProperty : annotationProperties.entrySet()) {
			if (!(annotationProperty.getValue() instanceof String)) {
				continue;
			}
			String expression = (String) annotationProperty.getValue();
			String value = helper.replacePlaceholders(expression, stringProperties::get);
			properties.put(annotationProperty.getKey(), value);
		}
		AnnotatedElement annotatedElement = (AnnotatedElement) mergedAnnotation.getSource();
		return MergedAnnotation.of(annotatedElement, this.type, properties);
	}

}
