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

import org.springframework.core.annotation.MergedAnnotation;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * A strategy for synthesizing an annotation from an {@link AnnotatedElement}.
 *
 * <p>
 * Synthesis generally refers to the process of taking an annotation's meta-annotations
 * and placeholders, resolving them, and then combining these elements into a facade of
 * the raw annotation instance.
 * </p>
 *
 * <p>
 * Since the process of synthesizing an annotation can be expensive, it is recommended to
 * cache the synthesized annotation to prevent multiple computations.
 * </p>
 *
 * @param <A> the annotation type
 * @author Josh Cummings
 * @since 6.4
 * @see UniqueMergedAnnotationSynthesizer
 * @see ExpressionTemplateAnnotationSynthesizer
 */
public interface AnnotationSynthesizer<A extends Annotation> {

	/**
	 * Synthesize an annotation of type {@code A} from the given {@link AnnotatedElement}.
	 *
	 * <p>
	 * Implementations should fail if they encounter more than one annotation of that type
	 * on the element.
	 * </p>
	 *
	 * <p>
	 * Implementations should describe their strategy for searching the element and any
	 * surrounding class, interfaces, or super-class.
	 * </p>
	 * @param element the element to search
	 * @return the synthesized annotation or {@code null} if not found
	 */
	@Nullable
	default A synthesize(AnnotatedElement element, Class<?> targetClass) {
		Assert.notNull(targetClass, "targetClass cannot be null");
		MergedAnnotation<A> annotation = merge(element, targetClass);
		if (annotation == null) {
			return null;
		}
		return annotation.synthesize();
	}

	@Nullable
	default A synthesize(AnnotatedElement element) {
		if (element instanceof Method method) {
			return synthesize(element, method.getDeclaringClass());
		}
		if (element instanceof Parameter parameter) {
			return synthesize(parameter, parameter.getDeclaringExecutable().getDeclaringClass());
		}
		throw new UnsupportedOperationException("Unsupported element of type " + element.getClass());
	}

	MergedAnnotation<A> merge(AnnotatedElement element, Class<?> targetClass);

}
