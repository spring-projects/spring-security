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

package org.springframework.security.core.annotation;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.jspecify.annotations.Nullable;

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
 *	public @interface HasRole {
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
 * Meta-annotations that use enum values can use {@link ExpressionTemplateValueProvider}
 * to provide custom placeholder values.
 *
 * <p>
 * Since the process of synthesis is expensive, it is recommended to cache the synthesized
 * result to prevent multiple computations.
 *
 * @param <A> the annotation to search for and synthesize
 * @author Josh Cummings
 * @author DingHao
 * @author Mike Heath
 * @since 7.0
 */
final class ExpressionTemplateSecurityAnnotationScanner<A extends Annotation>
		extends AbstractSecurityAnnotationScanner<A> {

	private static final DefaultConversionService conversionService = new DefaultConversionService();

	static {
		conversionService.addConverter(new ClassToStringConverter());
		conversionService.addConverter(new ExpressionTemplateValueProviderConverter());
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
	@Nullable MergedAnnotation<A> merge(AnnotatedElement element, @Nullable Class<?> targetClass) {
		if (element instanceof Parameter parameter) {
			return resolvePlaceholders(this.unique.merge(parameter, targetClass));
		}
		if (element instanceof Method method) {
			return resolvePlaceholders(this.unique.merge(method, targetClass));
		}
		throw new IllegalArgumentException("Unsupported element of type " + element.getClass());
	}

	private MergedAnnotation<A> resolvePlaceholders(MergedAnnotation<A> mergedAnnotation) {
		if (mergedAnnotation.getMetaSource() == null) {
			return mergedAnnotation;
		}
		PropertyPlaceholderHelper helper = new PropertyPlaceholderHelper("{", "}", null, null,
				this.templateDefaults.isIgnoreUnknown());
		Map<String, Object> properties = new HashMap<>(mergedAnnotation.asMap());
		Map<String, String> metaAnnotationProperties = extractMetaAnnotationProperties(mergedAnnotation);
		for (Map.Entry<String, Object> annotationProperty : mergedAnnotation.asMap().entrySet()) {
			if (!(annotationProperty.getValue() instanceof String expression)) {
				continue;
			}
			String value = helper.replacePlaceholders(expression, metaAnnotationProperties::get);
			properties.put(annotationProperty.getKey(), value);
		}
		AnnotatedElement annotatedElement = (AnnotatedElement) mergedAnnotation.getSource();
		return MergedAnnotation.of(annotatedElement, this.type, properties);
	}

	private Map<String, String> extractMetaAnnotationProperties(MergedAnnotation<A> mergedAnnotation) {
		Map<String, String> stringProperties = new HashMap<>();
		Map<String, Object> metaAnnotationProperties = new HashMap<>();
		MergedAnnotation<?> metaSource = mergedAnnotation.getMetaSource();
		while (metaSource != null) {
			metaAnnotationProperties.putAll(metaSource.asMap());
			metaSource = metaSource.getMetaSource();
		}
		for (Map.Entry<String, Object> property : metaAnnotationProperties.entrySet()) {
			Object value = property.getValue();
			String valueString = (value instanceof String) ? (String) value
					: conversionService.convert(value, String.class);
			stringProperties.put(property.getKey(), valueString);
		}
		return stringProperties;
	}

	static class ClassToStringConverter implements GenericConverter {

		@Override
		public Set<ConvertiblePair> getConvertibleTypes() {
			return Collections.singleton(new ConvertiblePair(Class.class, String.class));
		}

		@Override
		public @Nullable Object convert(@Nullable Object source, TypeDescriptor sourceType, TypeDescriptor targetType) {
			return (source != null) ? source.toString() : null;
		}

	}

	static class ExpressionTemplateValueProviderConverter implements GenericConverter {

		@Override
		public Set<ConvertiblePair> getConvertibleTypes() {
			return Collections.singleton(new ConvertiblePair(ExpressionTemplateValueProvider.class, String.class));
		}

		@Override
		public @Nullable Object convert(@Nullable Object source, TypeDescriptor sourceType, TypeDescriptor targetType) {
			return (source != null) ? ((ExpressionTemplateValueProvider) source).getExpressionTemplateValue() : null;
		}

	}

}
