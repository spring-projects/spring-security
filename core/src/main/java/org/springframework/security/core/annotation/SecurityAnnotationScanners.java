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
import java.util.ArrayList;
import java.util.List;

/**
 * Factory for creating {@link SecurityAnnotationScanner} instances.
 *
 * @author Josh Cummings
 * @since 6.4
 */
public final class SecurityAnnotationScanners {

	private SecurityAnnotationScanners() {
	}

	/**
	 * Create a {@link SecurityAnnotationScanner} that requires synthesized annotations to
	 * be unique on the given {@link AnnotatedElement}.
	 * @param type the annotation type
	 * @param <A> the annotation type
	 * @return the default {@link SecurityAnnotationScanner}
	 */
	public static <A extends Annotation> SecurityAnnotationScanner<A> requireUnique(Class<A> type) {
		return new UniqueSecurityAnnotationScanner<>(type);
	}

	/**
	 * Create a {@link SecurityAnnotationScanner} that requires synthesized annotations to
	 * be unique on the given {@link AnnotatedElement}.
	 *
	 * <p>
	 * When a {@link AnnotationTemplateExpressionDefaults} is provided, it will return a
	 * scanner that supports placeholders in the annotation's attributes in addition to
	 * the meta-annotation synthesizing provided by {@link #requireUnique(Class)}.
	 * @param type the annotation type
	 * @param templateDefaults the defaults for resolving placeholders in the annotation's
	 * attributes
	 * @param <A> the annotation type
	 * @return the default {@link SecurityAnnotationScanner}
	 */
	public static <A extends Annotation> SecurityAnnotationScanner<A> requireUnique(Class<A> type,
			AnnotationTemplateExpressionDefaults templateDefaults) {
		if (templateDefaults == null) {
			return new UniqueSecurityAnnotationScanner<>(type);
		}
		return new ExpressionTemplateSecurityAnnotationScanner<>(type, templateDefaults);
	}

	/**
	 * Create a {@link SecurityAnnotationScanner} that requires synthesized annotations to
	 * be unique on the given {@link AnnotatedElement}. Supplying multiple types implies
	 * that the synthesized annotation must be unique across all specified types.
	 * @param types the annotation types
	 * @return the default {@link SecurityAnnotationScanner}
	 */
	public static SecurityAnnotationScanner<Annotation> requireUnique(List<Class<? extends Annotation>> types) {
		List<Class<Annotation>> casted = new ArrayList<>();
		types.forEach((type) -> casted.add((Class<Annotation>) type));
		return new UniqueSecurityAnnotationScanner<>(casted);
	}

}
