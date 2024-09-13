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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.core.annotation.MergedAnnotation;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * An abstract class to hide the {@link MergedAnnotation} implementation details.
 *
 * <p>
 * Also, handy for allowing each scanner to delegate to another without needing to
 * synthesize twice.
 */
abstract class AbstractSecurityAnnotationScanner<A extends Annotation> implements SecurityAnnotationScanner<A> {

	private static final Map<AnnotatedElementKey, MergedAnnotation<?>> cachedMergedAnnotation = new ConcurrentHashMap<>();

	protected final List<Class<A>> types;

	AbstractSecurityAnnotationScanner(List<Class<A>> types) {
		Assert.noNullElements(types, "types cannot be null");
		this.types = types;
	}

	/**
	 * {@inheritDoc}
	 **/
	@Nullable
	@Override
	public A scan(Method method, Class<?> targetClass) {
		Assert.notNull(targetClass, "targetClass cannot be null");
		MergedAnnotation<A> annotation = mergedAnnotation(method, targetClass);
		if (annotation == null) {
			return null;
		}
		return annotation.synthesize();
	}

	@SuppressWarnings("unchecked")
	private MergedAnnotation<A> mergedAnnotation(AnnotatedElement element, Class<?> targetClass) {
		MergedAnnotation<A> mergedAnnotation = null;
		for (Class<A> type : this.types) {
			mergedAnnotation = (MergedAnnotation<A>) cachedMergedAnnotation
				.computeIfAbsent(new AnnotatedElementKey(element, type), (e) -> merge(element, targetClass));
			if (mergedAnnotation != null) {
				break;
			}
		}
		return mergedAnnotation;
	}

	/**
	 * {@inheritDoc}
	 **/
	@Nullable
	@Override
	public A scan(Parameter parameter) {
		MergedAnnotation<A> annotation = mergedAnnotation(parameter, null);
		if (annotation == null) {
			return null;
		}
		return annotation.synthesize();
	}

	abstract MergedAnnotation<A> merge(AnnotatedElement element, Class<?> targetClass);

	private record AnnotatedElementKey(AnnotatedElement element, Class<?> type) {

		@Override
		public boolean equals(Object o) {
			if (this == o) {
				return true;
			}
			if (o == null || getClass() != o.getClass()) {
				return false;
			}
			AnnotatedElementKey that = (AnnotatedElementKey) o;
			return Objects.equals(this.element, that.element) && Objects.equals(this.type, that.type);
		}

		@Override
		public int hashCode() {
			return Objects.hash(this.element, this.type);
		}

	}

}
