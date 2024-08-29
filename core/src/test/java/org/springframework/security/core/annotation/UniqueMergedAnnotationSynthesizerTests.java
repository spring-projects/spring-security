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

import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;

import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.prepost.PreAuthorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link UniqueMergedAnnotationSynthesizer}
 */
public class UniqueMergedAnnotationSynthesizerTests {

	private UniqueMergedAnnotationSynthesizer<PreAuthorize> synthesizer = new UniqueMergedAnnotationSynthesizer<>(
			PreAuthorize.class);

	@Test
	void synthesizeWhenAnnotationOnInterfaceThenResolves() throws Exception {
		Method method = AnnotationOnInterface.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("one");
	}

	@Test
	void synthesizeWhenAnnotationOnMethodThenResolves() throws Exception {
		Method method = AnnotationOnInterfaceMethod.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	@Test
	void synthesizeWhenAnnotationOnClassThenResolves() throws Exception {
		Method method = AnnotationOnClass.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("five");
	}

	@Test
	void synthesizeWhenAnnotationOnClassMethodThenResolves() throws Exception {
		Method method = AnnotationOnClassMethod.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("six");
	}

	@Test
	void synthesizeWhenInterfaceOverridingAnnotationOnInterfaceThenResolves() throws Exception {
		Method method = InterfaceMethodOverridingAnnotationOnInterface.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("eight");
	}

	@Test
	void synthesizeWhenInterfaceOverridingMultipleInterfaceInheritanceThenResolves() throws Exception {
		Method method = ClassInheritingInterfaceOverridingMultipleInterfaceInheritance.class
			.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("ten");
	}

	@Test
	void synthesizeWhenInterfaceMethodOverridingAnnotationOnInterfaceThenResolves() throws Exception {
		Method method = InterfaceMethodOverridingMultipleInterfaceInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("eleven");
	}

	@Test
	void synthesizeWhenClassMultipleInheritanceThenException() throws Exception {
		Method method = ClassAttemptingMultipleInterfaceInheritance.class.getDeclaredMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> this.synthesizer.synthesize(method, method.getDeclaringClass()));
	}

	// gh-15097
	@Test
	void synthesizeWhenClassOverridingMultipleInterfaceInheritanceThenResolves() throws Exception {
		Method method = ClassOverridingMultipleInterfaceInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("thirteen");
	}

	@Test
	void synthesizeWhenClassMethodOverridingMultipleInterfaceInheritanceThenResolves() throws Exception {
		Method method = ClassMethodOverridingMultipleInterfaceInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("fourteen");
	}

	@Test
	void synthesizeWhenClassInheritingInterfaceOverridingInterfaceAnnotationThenResolves() throws Exception {
		Method method = ClassInheritingInterfaceOverridingInterfaceAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("seven");
	}

	@Test
	void synthesizeWhenClassOverridingGrandparentInterfaceAnnotationThenResolves() throws Exception {
		Method method = ClassOverridingGrandparentInterfaceAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("sixteen");
	}

	@Test
	void synthesizeWhenMethodOverridingGrandparentInterfaceAnnotationThenResolves() throws Exception {
		Method method = MethodOverridingGrandparentInterfaceAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("seventeen");
	}

	@Test
	void synthesizeWhenClassInheritingMethodOverriddenAnnotationThenResolves() throws Exception {
		Method method = ClassInheritingMethodOverriddenAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("eight");
	}

	@Test
	void synthesizeWhenClassOverridingMethodOverriddenAnnotationThenResolves() throws Exception {
		Method method = ClassOverridingMethodOverriddenAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("eight");
	}

	@Test
	void synthesizeWhenMethodOverridingMethodOverriddenAnnotationThenResolves() throws Exception {
		Method method = MethodOverridingMethodOverriddenAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twenty");
	}

	@Test
	void synthesizeWhenClassInheritingMultipleInheritanceThenException() throws Exception {
		Method method = ClassInheritingMultipleInheritance.class.getDeclaredMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> this.synthesizer.synthesize(method, method.getDeclaringClass()));
	}

	@Test
	void synthesizeWhenClassOverridingMultipleInheritanceThenResolves() throws Exception {
		Method method = ClassOverridingMultipleInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentytwo");
	}

	@Test
	void synthesizeWhenMethodOverridingMultipleInheritanceThenResolves() throws Exception {
		Method method = MethodOverridingMultipleInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentythree");
	}

	@Test
	void synthesizeWhenInheritingInterfaceAndMethodAnnotationsThenResolves() throws Exception {
		Method method = InheritingInterfaceAndMethodAnnotations.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	@Test
	void synthesizeWhenClassOverridingInterfaceAndMethodInheritanceThenResolves() throws Exception {
		Method method = ClassOverridingInterfaceAndMethodInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	@Test
	void synthesizeWhenMethodOverridingInterfaceAndMethodInheritanceThenResolves() throws Exception {
		Method method = MethodOverridingInterfaceAndMethodInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentysix");
	}

	@Test
	void synthesizeWhenMultipleMethodInheritanceThenException() throws Exception {
		Method method = MultipleMethodInheritance.class.getDeclaredMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> this.synthesizer.synthesize(method, method.getDeclaringClass()));
	}

	// gh-13234
	@Test
	void synthesizeWhenClassInheritingInterfaceAnnotationThenResolves() throws Exception {
		Method method = ClassInheritingInterfaceMethodAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	@Test
	void synthesizeWhenMethodInheritingMethodOverridingInterfaceAndMethodInheritanceThenResolves() throws Exception {
		Method method = MethodInheritingMethodOverridingInterfaceAndMethodInheritance.class.getMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentysix");
	}

	@Test
	void synthesizeWhenClassOverridingMethodOverridingInterfaceAndMethodInheritanceThenResolves() throws Exception {
		Method method = ClassOverridingMethodOverridingInterfaceAndMethodInheritance.class.getMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method,
				ClassOverridingMethodOverridingInterfaceAndMethodInheritance.class);
		assertThat(preAuthorize.value()).isEqualTo("twentysix");
	}

	@Test
	void synthesizeWhenInterfaceInheritingAnnotationsAtDifferentLevelsThenException() throws Exception {
		Method method = InterfaceInheritingAnnotationsAtDifferentLevels.class.getMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> this.synthesizer.synthesize(method, method.getDeclaringClass()));
	}

	@Test
	void synthesizeWhenClassMethodOverridingAnnotationOnMethodThenResolves() throws Exception {
		Method method = ClassMethodOverridingAnnotationOnMethod.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentyeight");
	}

	// gh-13490
	@Test
	void synthesizeWhenClassInheritingInterfaceInheritingInterfaceMethodAnnotationThenResolves() throws Exception {
		Method method = ClassInheritingInterfaceInheritingInterfaceMethodAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	// gh-15352
	@Test
	void synthesizeWhenClassInheritingAbstractClassNoAnnotationsThenNoAnnotation() throws Exception {
		Method method = ClassInheritingAbstractClassNoAnnotations.class.getMethod("otherMethod");
		Class<?> targetClass = ClassInheritingAbstractClassNoAnnotations.class;
		PreAuthorize preAuthorize = this.synthesizer.synthesize(method, targetClass);
		assertThat(preAuthorize).isNull();
	}

	@PreAuthorize("one")
	private interface AnnotationOnInterface {

		String method();

	}

	@PreAuthorize("two")
	private interface AlsoAnnotationOnInterface {

		String method();

	}

	private interface AnnotationOnInterfaceMethod {

		@PreAuthorize("three")
		String method();

	}

	private interface AlsoAnnotationOnInterfaceMethod {

		@PreAuthorize("four")
		String method();

	}

	@PreAuthorize("five")
	private static class AnnotationOnClass {

		String method() {
			return "ok";
		}

	}

	private static class AnnotationOnClassMethod {

		@PreAuthorize("six")
		String method() {
			return "ok";
		}

	}

	@PreAuthorize("seven")
	private interface InterfaceOverridingAnnotationOnInterface extends AnnotationOnInterface {

	}

	private interface InterfaceMethodOverridingAnnotationOnInterface extends AnnotationOnInterface {

		@PreAuthorize("eight")
		String method();

	}

	private interface InterfaceAttemptingMultipleInterfaceInheritance
			extends AnnotationOnInterface, AlsoAnnotationOnInterface {

	}

	@PreAuthorize("ten")
	private interface InterfaceOverridingMultipleInterfaceInheritance
			extends AnnotationOnInterface, AlsoAnnotationOnInterface {

	}

	private static class ClassInheritingInterfaceOverridingMultipleInterfaceInheritance
			implements InterfaceOverridingMultipleInterfaceInheritance {

		@Override
		public String method() {
			return "ok";
		}

	}

	private interface InterfaceMethodOverridingMultipleInterfaceInheritance
			extends AnnotationOnInterface, AlsoAnnotationOnInterface {

		@PreAuthorize("eleven")
		String method();

	}

	private static class ClassAttemptingMultipleInterfaceInheritance
			implements AnnotationOnInterface, AlsoAnnotationOnInterface {

		@Override
		public String method() {
			return "ok";
		}

	}

	@PreAuthorize("thirteen")
	private static class ClassOverridingMultipleInterfaceInheritance
			implements AnnotationOnInterface, AlsoAnnotationOnInterface {

		@Override
		public String method() {
			return "ok";
		}

	}

	private static class ClassMethodOverridingMultipleInterfaceInheritance
			implements AnnotationOnInterface, AlsoAnnotationOnInterface {

		@Override
		@PreAuthorize("fourteen")
		public String method() {
			return "ok";
		}

	}

	private static class ClassInheritingInterfaceOverridingInterfaceAnnotation
			implements InterfaceOverridingAnnotationOnInterface {

		@Override
		public String method() {
			return "ok";
		}

	}

	@PreAuthorize("sixteen")
	private static class ClassOverridingGrandparentInterfaceAnnotation
			implements InterfaceOverridingAnnotationOnInterface {

		@Override
		public String method() {
			return "ok";
		}

	}

	private static class MethodOverridingGrandparentInterfaceAnnotation
			implements InterfaceOverridingAnnotationOnInterface {

		@Override
		@PreAuthorize("seventeen")
		public String method() {
			return "ok";
		} // unambiguously seventeen

	}

	private static class ClassInheritingMethodOverriddenAnnotation
			implements InterfaceMethodOverridingAnnotationOnInterface {

		@Override
		public String method() {
			return "ok";
		}

	}

	@PreAuthorize("nineteen")
	private static class ClassOverridingMethodOverriddenAnnotation
			implements InterfaceMethodOverridingAnnotationOnInterface {

		@Override
		public String method() {
			return "ok";
		}

	}

	private static class MethodOverridingMethodOverriddenAnnotation
			implements InterfaceMethodOverridingAnnotationOnInterface {

		@Override
		@PreAuthorize("twenty")
		public String method() {
			return "ok";
		}

	}

	private static class ClassInheritingMultipleInheritance implements InterfaceAttemptingMultipleInterfaceInheritance {

		@Override
		public String method() {
			return "ok";
		}

	}

	@PreAuthorize("twentytwo")
	private static class ClassOverridingMultipleInheritance implements InterfaceAttemptingMultipleInterfaceInheritance {

		@Override
		public String method() {
			return "ok";
		}

	}

	private static class MethodOverridingMultipleInheritance
			implements InterfaceAttemptingMultipleInterfaceInheritance {

		@Override
		@PreAuthorize("twentythree")
		public String method() {
			return "ok";
		}

	}

	private static class InheritingInterfaceAndMethodAnnotations
			implements AnnotationOnInterface, AnnotationOnInterfaceMethod {

		@Override
		public String method() {
			return "ok";
		}

	}

	@PreAuthorize("twentyfive")
	private static class ClassOverridingInterfaceAndMethodInheritance
			implements AnnotationOnInterface, AnnotationOnInterfaceMethod {

		@Override
		public String method() {
			return "ok";
		}

	}

	private static class MethodOverridingInterfaceAndMethodInheritance
			implements AnnotationOnInterface, AnnotationOnInterfaceMethod {

		@Override
		@PreAuthorize("twentysix")
		public String method() {
			return "ok";
		}

	}

	private static class MultipleMethodInheritance
			implements AnnotationOnInterfaceMethod, AlsoAnnotationOnInterfaceMethod {

		@Override
		public String method() {
			return "ok";
		}

	}

	private interface InterfaceInheritingInterfaceAnnotation extends AnnotationOnInterface {

	}

	private static class ClassInheritingInterfaceMethodAnnotation implements AnnotationOnInterfaceMethod {

		@Override
		public String method() {
			return "ok";
		}

	}

	private static class MethodInheritingMethodOverridingInterfaceAndMethodInheritance
			extends MethodOverridingInterfaceAndMethodInheritance {

	}

	@PreAuthorize("twentyseven")
	private static class ClassOverridingMethodOverridingInterfaceAndMethodInheritance
			extends MethodOverridingInterfaceAndMethodInheritance {

	}

	private static class InterfaceInheritingAnnotationsAtDifferentLevels
			implements InterfaceInheritingInterfaceAnnotation, AlsoAnnotationOnInterface {

		@Override
		public String method() {
			return "ok";
		}

	}

	private static class ClassMethodOverridingAnnotationOnMethod implements AnnotationOnInterfaceMethod {

		@Override
		@PreAuthorize("twentyeight")
		public String method() {
			return "ok";
		}

	}

	private interface InterfaceInheritingInterfaceMethodAnnotation extends AnnotationOnInterfaceMethod {

	}

	private static class ClassInheritingInterfaceInheritingInterfaceMethodAnnotation
			implements InterfaceInheritingInterfaceMethodAnnotation {

		@Override
		public String method() {
			return "ok";
		}

	}

	public abstract static class AbstractClassNoAnnotations {

		public String otherMethod() {
			return "ok";
		}

	}

	@PreAuthorize("twentynine")
	private static class ClassInheritingAbstractClassNoAnnotations extends AbstractClassNoAnnotations {

	}

}
