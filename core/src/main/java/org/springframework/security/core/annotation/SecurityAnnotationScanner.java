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
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

import org.springframework.lang.Nullable;

/**
 * An interface to scan for and synthesize an annotation on a type, method, or method
 * parameter into an annotation of type {@code <A>}.
 *
 * <p>
 * Implementations should support meta-annotations. This is usually by way of the
 * {@link org.springframework.core.annotation.MergedAnnotations} API.
 *
 * <p>
 * Synthesis generally refers to the process of taking an annotation's meta-annotations
 * and placeholders, resolving them, and then combining these elements into a facade of
 * the raw annotation instance.
 *
 * <p>
 * Since the process of synthesizing an annotation can be expensive, it's recommended to
 * cache the synthesized annotation to prevent multiple computations.
 * </p>
 *
 * @param <A> the annotation to search for and synthesize
 * @author Josh Cummings
 * @since 6.4
 * @see UniqueSecurityAnnotationScanner
 * @see ExpressionTemplateSecurityAnnotationScanner
 */
public interface SecurityAnnotationScanner<A extends Annotation> {

	/**
	 * Scan for an annotation of type {@code A}, starting from the given method.
	 *
	 * <p>
	 * Implementations should fail if they encounter more than one annotation of that type
	 * attributable to the method.
	 *
	 * <p>
	 * Implementations should describe their strategy for searching the element and any
	 * surrounding class, interfaces, or super-class.
	 * @param method the method to search from
	 * @param targetClass the target class for the method
	 * @return the synthesized annotation or {@code null} if not found
	 */
	@Nullable
	A scan(Method method, Class<?> targetClass);

	/**
	 * Scan for an annotation of type {@code A}, starting from the given method parameter.
	 *
	 * <p>
	 * Implementations should fail if they encounter more than one annotation of that type
	 * attributable to the parameter.
	 *
	 * <p>
	 * Implementations should describe their strategy for searching the element and any
	 * surrounding class, interfaces, or super-class.
	 * @param element the element to search
	 * @return the synthesized annotation or {@code null} if not found
	 */
	@Nullable
	A scan(Parameter parameter);

}
