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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.prepost.PreAuthorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link UniqueSecurityAnnotationScanner}
 */
public class UniqueSecurityAnnotationScannerTests {

	private UniqueSecurityAnnotationScanner<PreAuthorize> scanner = new UniqueSecurityAnnotationScanner<>(
			PreAuthorize.class);

	private UniqueSecurityAnnotationScanner<CustomParameterAnnotation> parameterScanner = new UniqueSecurityAnnotationScanner<>(
			CustomParameterAnnotation.class);

	@Test
	void scanWhenAnnotationOnInterfaceThenResolves() throws Exception {
		Method method = AnnotationOnInterface.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("one");
	}

	@Test
	void scanWhenAnnotationOnMethodThenResolves() throws Exception {
		Method method = AnnotationOnInterfaceMethod.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	@Test
	void scanWhenAnnotationOnClassThenResolves() throws Exception {
		Method method = AnnotationOnClass.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("five");
	}

	@Test
	void scanWhenAnnotationOnClassMethodThenResolves() throws Exception {
		Method method = AnnotationOnClassMethod.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("six");
	}

	@Test
	void scanWhenInterfaceOverridingAnnotationOnInterfaceThenResolves() throws Exception {
		Method method = InterfaceMethodOverridingAnnotationOnInterface.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("eight");
	}

	@Test
	void scanWhenInterfaceOverridingMultipleInterfaceInheritanceThenResolves() throws Exception {
		Method method = ClassInheritingInterfaceOverridingMultipleInterfaceInheritance.class
			.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("ten");
	}

	@Test
	void scanWhenInterfaceMethodOverridingAnnotationOnInterfaceThenResolves() throws Exception {
		Method method = InterfaceMethodOverridingMultipleInterfaceInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("eleven");
	}

	@Test
	void scanWhenClassMultipleInheritanceThenException() throws Exception {
		Method method = ClassAttemptingMultipleInterfaceInheritance.class.getDeclaredMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> this.scanner.scan(method, method.getDeclaringClass()));
	}

	// gh-15097
	@Test
	void scanWhenClassOverridingMultipleInterfaceInheritanceThenResolves() throws Exception {
		Method method = ClassOverridingMultipleInterfaceInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("thirteen");
	}

	@Test
	void scanWhenClassMethodOverridingMultipleInterfaceInheritanceThenResolves() throws Exception {
		Method method = ClassMethodOverridingMultipleInterfaceInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("fourteen");
	}

	@Test
	void scanWhenClassInheritingInterfaceOverridingInterfaceAnnotationThenResolves() throws Exception {
		Method method = ClassInheritingInterfaceOverridingInterfaceAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("seven");
	}

	@Test
	void scanWhenClassOverridingGrandparentInterfaceAnnotationThenResolves() throws Exception {
		Method method = ClassOverridingGrandparentInterfaceAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("sixteen");
	}

	@Test
	void scanWhenMethodOverridingGrandparentInterfaceAnnotationThenResolves() throws Exception {
		Method method = MethodOverridingGrandparentInterfaceAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("seventeen");
	}

	@Test
	void scanWhenClassInheritingMethodOverriddenAnnotationThenResolves() throws Exception {
		Method method = ClassInheritingMethodOverriddenAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("eight");
	}

	@Test
	void scanWhenClassOverridingMethodOverriddenAnnotationThenResolves() throws Exception {
		Method method = ClassOverridingMethodOverriddenAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("eight");
	}

	@Test
	void scanWhenMethodOverridingMethodOverriddenAnnotationThenResolves() throws Exception {
		Method method = MethodOverridingMethodOverriddenAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twenty");
	}

	@Test
	void scanWhenClassInheritingMultipleInheritanceThenException() throws Exception {
		Method method = ClassInheritingMultipleInheritance.class.getDeclaredMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> this.scanner.scan(method, method.getDeclaringClass()));
	}

	@Test
	void scanWhenClassOverridingMultipleInheritanceThenResolves() throws Exception {
		Method method = ClassOverridingMultipleInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentytwo");
	}

	@Test
	void scanWhenMethodOverridingMultipleInheritanceThenResolves() throws Exception {
		Method method = MethodOverridingMultipleInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentythree");
	}

	@Test
	void scanWhenInheritingInterfaceAndMethodAnnotationsThenResolves() throws Exception {
		Method method = InheritingInterfaceAndMethodAnnotations.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	@Test
	void scanWhenClassOverridingInterfaceAndMethodInheritanceThenResolves() throws Exception {
		Method method = ClassOverridingInterfaceAndMethodInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	@Test
	void scanWhenMethodOverridingInterfaceAndMethodInheritanceThenResolves() throws Exception {
		Method method = MethodOverridingInterfaceAndMethodInheritance.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentysix");
	}

	@Test
	void scanWhenMultipleMethodInheritanceThenException() throws Exception {
		Method method = MultipleMethodInheritance.class.getDeclaredMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> this.scanner.scan(method, method.getDeclaringClass()));
	}

	// gh-13234
	@Test
	void scanWhenClassInheritingInterfaceAnnotationThenResolves() throws Exception {
		Method method = ClassInheritingInterfaceMethodAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	@Test
	void scanWhenMethodInheritingMethodOverridingInterfaceAndMethodInheritanceThenResolves() throws Exception {
		Method method = MethodInheritingMethodOverridingInterfaceAndMethodInheritance.class.getMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentysix");
	}

	@Test
	void scanWhenClassOverridingMethodOverridingInterfaceAndMethodInheritanceThenResolves() throws Exception {
		Method method = ClassOverridingMethodOverridingInterfaceAndMethodInheritance.class.getMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method,
				ClassOverridingMethodOverridingInterfaceAndMethodInheritance.class);
		assertThat(preAuthorize.value()).isEqualTo("twentysix");
	}

	@Test
	void scanWhenInterfaceInheritingAnnotationsAtDifferentLevelsThenException() throws Exception {
		Method method = InterfaceInheritingAnnotationsAtDifferentLevels.class.getMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> this.scanner.scan(method, method.getDeclaringClass()));
	}

	@Test
	void scanWhenClassMethodOverridingAnnotationOnMethodThenResolves() throws Exception {
		Method method = ClassMethodOverridingAnnotationOnMethod.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentyeight");
	}

	// gh-13490
	@Test
	void scanWhenClassInheritingInterfaceInheritingInterfaceMethodAnnotationThenResolves() throws Exception {
		Method method = ClassInheritingInterfaceInheritingInterfaceMethodAnnotation.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	// gh-15352
	@Test
	void scanWhenClassInheritingAbstractClassNoAnnotationsThenNoAnnotation() throws Exception {
		Method method = ClassInheritingAbstractClassNoAnnotations.class.getMethod("otherMethod");
		Class<?> targetClass = ClassInheritingAbstractClassNoAnnotations.class;
		PreAuthorize preAuthorize = this.scanner.scan(method, targetClass);
		assertThat(preAuthorize).isNull();
	}

	@Test
	void scanParameterAnnotationWhenAnnotationOnInterface() throws Exception {
		Parameter parameter = UserService.class.getDeclaredMethod("add", String.class).getParameters()[0];
		CustomParameterAnnotation customParameterAnnotation = this.parameterScanner.scan(parameter);
		assertThat(customParameterAnnotation.value()).isEqualTo("one");
	}

	@Test
	void scanParameterAnnotationWhenClassInheritingInterfaceAnnotation() throws Exception {
		Parameter parameter = UserServiceImpl.class.getDeclaredMethod("add", String.class).getParameters()[0];
		CustomParameterAnnotation customParameterAnnotation = this.parameterScanner.scan(parameter);
		assertThat(customParameterAnnotation.value()).isEqualTo("one");
	}

	@Test
	void scanParameterAnnotationWhenClassOverridingMethodOverridingInterface() throws Exception {
		Parameter parameter = UserServiceImpl.class.getDeclaredMethod("get", String.class).getParameters()[0];
		CustomParameterAnnotation customParameterAnnotation = this.parameterScanner.scan(parameter);
		assertThat(customParameterAnnotation.value()).isEqualTo("five");
	}

	@Test
	void scanParameterAnnotationWhenMultipleMethodInheritanceThenException() throws Exception {
		Parameter parameter = UserServiceImpl.class.getDeclaredMethod("list", String.class).getParameters()[0];
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> this.parameterScanner.scan(parameter));
	}

	@Test
	void scanParameterAnnotationWhenInterfaceNoAnnotationsThenException() throws Exception {
		Parameter parameter = UserServiceImpl.class.getDeclaredMethod("delete", String.class).getParameters()[0];
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> this.parameterScanner.scan(parameter));
	}

	interface UserService {

		void add(@CustomParameterAnnotation("one") String user);

		List<String> list(@CustomParameterAnnotation("two") String user);

		String get(@CustomParameterAnnotation("three") String user);

		void delete(@CustomParameterAnnotation("five") String user);

	}

	interface OtherUserService {

		List<String> list(@CustomParameterAnnotation("four") String user);

	}

	interface ThirdPartyUserService {

		void delete(@CustomParameterAnnotation("five") String user);

	}

	interface RemoteUserService extends ThirdPartyUserService {

	}

	static class UserServiceImpl implements UserService, OtherUserService, RemoteUserService {

		@Override
		public void add(String user) {

		}

		@Override
		public List<String> list(String user) {
			return List.of(user);
		}

		@Override
		public String get(@CustomParameterAnnotation("five") String user) {
			return user;
		}

		@Override
		public void delete(String user) {

		}

	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@interface CustomParameterAnnotation {

		String value();

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
