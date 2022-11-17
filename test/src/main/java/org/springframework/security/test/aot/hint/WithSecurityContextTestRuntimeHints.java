/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.test.aot.hint;

import java.util.Arrays;
import java.util.stream.Stream;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.core.annotation.MergedAnnotation;
import org.springframework.core.annotation.MergedAnnotations;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.test.context.aot.TestRuntimeHintsRegistrar;

import static org.springframework.core.annotation.MergedAnnotations.SearchStrategy.SUPERCLASS;

/**
 * {@link TestRuntimeHintsRegistrar} implementation that register runtime hints for
 * {@link WithSecurityContext#factory()} classes.
 *
 * @author Marcus da Coregio
 * @since 6.0
 */
class WithSecurityContextTestRuntimeHints implements TestRuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, Class<?> testClass, ClassLoader classLoader) {
		Stream.concat(getClassAnnotations(testClass), getMethodAnnotations(testClass))
				.filter(MergedAnnotation::isPresent)
				.map((withSecurityContext) -> withSecurityContext.getClass("factory"))
				.forEach((factory) -> registerDeclaredConstructors(hints, factory));
	}

	private Stream<MergedAnnotation<WithSecurityContext>> getClassAnnotations(Class<?> testClass) {
		return MergedAnnotations.search(SUPERCLASS).from(testClass).stream(WithSecurityContext.class);
	}

	private Stream<MergedAnnotation<WithSecurityContext>> getMethodAnnotations(Class<?> testClass) {
		return Arrays.stream(testClass.getDeclaredMethods())
				.map((method) -> MergedAnnotations.from(method, SUPERCLASS).get(WithSecurityContext.class));
	}

	private void registerDeclaredConstructors(RuntimeHints hints, Class<?> factory) {
		hints.reflection().registerType(factory, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS);
	}

}
