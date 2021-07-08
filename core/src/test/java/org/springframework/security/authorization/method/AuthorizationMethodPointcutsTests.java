/*
 * Copyright 2002-2021 the original author or authors.
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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.Test;

import org.springframework.aop.Pointcut;
import org.springframework.aop.support.AopUtils;
import org.springframework.security.access.prepost.PreAuthorize;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AuthorizationMethodPointcuts}
 */
public class AuthorizationMethodPointcutsTests {

	@Test
	public void forAnnotationsWhenAnnotationThenClassBasedAnnotationPointcut() {
		Pointcut preAuthorize = AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class);
		assertThat(AopUtils.canApply(preAuthorize, ClassController.class)).isTrue();
		assertThat(AopUtils.canApply(preAuthorize, NoController.class)).isFalse();
	}

	@Test
	public void forAnnotationsWhenAnnotationThenMethodBasedAnnotationPointcut() {
		Pointcut preAuthorize = AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class);
		assertThat(AopUtils.canApply(preAuthorize, MethodController.class)).isTrue();
	}

	@Test
	public void forAnnotationsWhenAnnotationThenClassInheritancePointcut() {
		Pointcut preAuthorize = AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class);
		assertThat(AopUtils.canApply(preAuthorize, InterfacedClassController.class)).isTrue();
	}

	@Test
	public void forAnnotationsWhenAnnotationThenMethodInheritancePointcut() {
		Pointcut preAuthorize = AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class);
		assertThat(AopUtils.canApply(preAuthorize, InterfacedMethodController.class)).isTrue();
	}

	@Test
	public void forAnnotationsWhenAnnotationThenAnnotationClassInheritancePointcut() {
		Pointcut preAuthorize = AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class);
		assertThat(AopUtils.canApply(preAuthorize, InterfacedAnnotationClassController.class)).isTrue();
	}

	@Test
	public void forAnnotationsWhenAnnotationThenAnnotationMethodInheritancePointcut() {
		Pointcut preAuthorize = AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class);
		assertThat(AopUtils.canApply(preAuthorize, InterfacedAnnotationMethodController.class)).isTrue();
	}

	@PreAuthorize("hasAuthority('APP')")
	public static class ClassController {

		String methodOne(String paramOne) {
			return "value";
		}

	}

	public static class MethodController {

		@PreAuthorize("hasAuthority('APP')")
		String methodOne(String paramOne) {
			return "value";
		}

	}

	public static class NoController {

		String methodOne(String paramOne) {
			return "value";
		}

	}

	@PreAuthorize("hasAuthority('APP')")
	public interface ClassControllerInterface {

		String methodOne(String paramOne);

	}

	public static class InterfacedClassController implements ClassControllerInterface {

		public String methodOne(String paramOne) {
			return "value";
		}

	}

	public interface MethodControllerInterface {

		@PreAuthorize("hasAuthority('APP')")
		String methodOne(String paramOne);

	}

	public static class InterfacedMethodController implements MethodControllerInterface {

		public String methodOne(String paramOne) {
			return "value";
		}

	}

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("hasAuthority('APP')")
	@interface MyAnnotation {

	}

	@MyAnnotation
	public interface ClassAnnotationControllerInterface {

		String methodOne(String paramOne);

	}

	public static class InterfacedAnnotationClassController implements ClassAnnotationControllerInterface {

		public String methodOne(String paramOne) {
			return "value";
		}

	}

	public interface MethodAnnotationControllerInterface {

		@MyAnnotation
		String methodOne(String paramOne);

	}

	public static class InterfacedAnnotationMethodController implements MethodAnnotationControllerInterface {

		public String methodOne(String paramOne) {
			return "value";
		}

	}

}
