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

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.core.annotation.AliasFor;
import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.prepost.PreAuthorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link AuthorizationAnnotationUtils}.
 *
 * @author Josh Cummings
 * @author Sam Brannen
 */
class AuthorizationAnnotationUtilsTests {

	@Test // gh-13132
	void annotationsOnSyntheticMethodsShouldNotTriggerAnnotationConfigurationException() throws NoSuchMethodException {
		StringRepository proxy = (StringRepository) Proxy.newProxyInstance(
				Thread.currentThread().getContextClassLoader(), new Class[] { StringRepository.class },
				(p, m, args) -> null);
		Method method = proxy.getClass().getDeclaredMethod("findAll");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreAuthorize.class);
		assertThat(preAuthorize.value()).isEqualTo("hasRole('someRole')");
	}

	@Test // gh-13625
	void annotationsFromSuperSuperInterfaceShouldNotTriggerAnnotationConfigurationException() throws Exception {
		Method method = HelloImpl.class.getDeclaredMethod("sayHello");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreAuthorize.class);
		assertThat(preAuthorize.value()).isEqualTo("hasRole('someRole')");
	}

	@Test
	void multipleIdenticalAnnotationsOnClassShouldNotTriggerAnnotationConfigurationException() {
		Class<?> clazz = MultipleIdenticalPreAuthorizeAnnotationsOnClass.class;
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(clazz, PreAuthorize.class);
		assertThat(preAuthorize.value()).isEqualTo("hasRole('someRole')");
	}

	@Test
	void multipleIdenticalAnnotationsOnMethodShouldNotTriggerAnnotationConfigurationException() throws Exception {
		Method method = MultipleIdenticalPreAuthorizeAnnotationsOnMethod.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreAuthorize.class);
		assertThat(preAuthorize.value()).isEqualTo("hasRole('someRole')");
	}

	@Test
	void competingAnnotationsOnClassShouldTriggerAnnotationConfigurationException() {
		Class<?> clazz = CompetingPreAuthorizeAnnotationsOnClass.class;
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> AuthorizationAnnotationUtils.findUniqueAnnotation(clazz, PreAuthorize.class))
			.withMessageContainingAll("Found 2 competing annotations:", "someRole", "otherRole");
	}

	@Test
	void competingAnnotationsOnMethodShouldTriggerAnnotationConfigurationException() throws Exception {
		Method method = CompetingPreAuthorizeAnnotationsOnMethod.class.getDeclaredMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreAuthorize.class))
			.withMessageContainingAll("Found 2 competing annotations:", "someRole", "otherRole");
	}

	@Test
	void composedMergedAnnotationsAreNotSupported() {
		Class<?> clazz = ComposedPreAuthAnnotationOnClass.class;
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(clazz, PreAuthorize.class);

		// If you comment out .map(MergedAnnotation::withNonMergedAttributes) in
		// AuthorizationAnnotationUtils.findDistinctAnnotation(), the value of
		// the merged annotation would be "hasRole('composedRole')".
		assertThat(preAuthorize.value()).isEqualTo("hasRole('metaRole')");
	}

	private interface BaseRepository<T> {

		Iterable<T> findAll();

	}

	private interface StringRepository extends BaseRepository<String> {

		@Override
		@PreAuthorize("hasRole('someRole')")
		List<String> findAll();

	}

	private interface Hello {

		@PreAuthorize("hasRole('someRole')")
		String sayHello();

	}

	private interface SayHello extends Hello {

	}

	private static class HelloImpl implements SayHello {

		@Override
		public String sayHello() {
			return "hello";
		}

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("hasRole('someRole')")
	private @interface RequireSomeRole {

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("hasRole('otherRole')")
	private @interface RequireOtherRole {

	}

	@RequireSomeRole
	@PreAuthorize("hasRole('someRole')")
	private static class MultipleIdenticalPreAuthorizeAnnotationsOnClass {

	}

	private static class MultipleIdenticalPreAuthorizeAnnotationsOnMethod {

		@RequireSomeRole
		@PreAuthorize("hasRole('someRole')")
		void method() {
		}

	}

	@RequireOtherRole
	@PreAuthorize("hasRole('someRole')")
	private static class CompetingPreAuthorizeAnnotationsOnClass {

	}

	private static class CompetingPreAuthorizeAnnotationsOnMethod {

		@RequireOtherRole
		@PreAuthorize("hasRole('someRole')")
		void method() {
		}

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("hasRole('metaRole')")
	private @interface ComposedPreAuth {

		@AliasFor(annotation = PreAuthorize.class)
		String value();

	}

	@ComposedPreAuth("hasRole('composedRole')")
	private static class ComposedPreAuthAnnotationOnClass {

	}

}
