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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.core.annotation.MergedAnnotation;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.GenericConverter;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.util.Assert;
import org.springframework.util.PropertyPlaceholderHelper;

/**
 * Searches for and synthesizes an annotation on a type, method, or method parameter into
 * an annotation of type {@code <A>}, resolving any placeholders in the annotation value.
 *
 * <p>
 * Note that in all cases, Spring Security does not allow for repeatable annotations. So
 * this class delegates to {@link UniqueSecurityAnnotationScanner} in order to error if a
 * repeat is discovered.
 *
 * <p>
 * It supports meta-annotations with placeholders, like the following:
 *
 * <pre>
 *	&#64;PreAuthorize("hasRole({role})")
 *	public @annotation HasRole {
 *		String role();
 *	}
 * </pre>
 *
 * <p>
 * In that case, you could use an {@link ExpressionTemplateSecurityAnnotationScanner} of
 * type {@link org.springframework.security.access.prepost.PreAuthorize} to synthesize any
 * {@code @HasRole} annotation found on a given {@link AnnotatedElement}.
 *
 * <p>
 * Since the process of synthesis is expensive, it is recommended to cache the synthesized
 * result to prevent multiple computations.
 *
 * @param <A> the annotation to search for and synthesize
 * @author Josh Cummings
 * @since 6.4
 */
final class ExpressionTemplateSecurityAnnotationScanner<A extends Annotation>
		extends AbstractSecurityAnnotationScanner<A> {

	private static final DefaultConversionService conversionService = new DefaultConversionService();

	static {
		conversionService.addConverter(new ClassToStringConverter());
	}

	private final Class<A> type;

	private final UniqueSecurityAnnotationScanner<A> unique;

	private final AnnotationTemplateExpressionDefaults templateDefaults;

	ExpressionTemplateSecurityAnnotationScanner(Class<A> type, AnnotationTemplateExpressionDefaults templateDefaults) {
		Assert.notNull(type, "type cannot be null");
		Assert.notNull(templateDefaults, "templateDefaults cannot be null");
		this.type = type;
		this.unique = new UniqueSecurityAnnotationScanner<>(type);
		this.templateDefaults = templateDefaults;
	}

	@Override
	MergedAnnotation<A> merge(AnnotatedElement element, Class<?> targetClass) {
		if (element instanceof Parameter parameter) {
			MergedAnnotation<A> annotation = this.unique.merge(parameter, targetClass);
			if (annotation == null) {
				return null;
			}
			return resolvePlaceholders(annotation);
		}
		if (element instanceof Method method) {
			MergedAnnotation<A> annotation = this.unique.merge(method, targetClass);
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
					: conversionService.convert(value, String.class);
			stringProperties.put(key, asString);
		}
		Map<String, Object> annotationProperties = mergedAnnotation.asMap();
		for (Map.Entry<String, Object> annotationProperty : annotationProperties.entrySet()) {
			if (!(annotationProperty.getValue() instanceof String expression)) {
				continue;
			}
			String value = helper.replacePlaceholders(expression, stringProperties::get);
			properties.put(annotationProperty.getKey(), value);
		}
		AnnotatedElement annotatedElement = (AnnotatedElement) mergedAnnotation.getSource();
		return MergedAnnotation.of(annotatedElement, this.type, properties);
	}

	static class ClassToStringConverter implements GenericConverter {

		@Override
		public Set<ConvertiblePair> getConvertibleTypes() {
			return Collections.singleton(new ConvertiblePair(Class.class, String.class));
		}

		@Override
		public Object convert(Object source, TypeDescriptor sourceType, TypeDescriptor targetType) {
			return (source != null) ? source.toString() : null;
		}

	}

}
