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

package org.springframework.security.authorization.method;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import org.springframework.aop.TargetClassAware;
import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PreAuthorizeAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public class PreAuthorizeAuthorizationManagerTests {

	@Test
	public void setExpressionHandlerWhenNotNullThenSetsExpressionHandler() {
		MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		manager.setExpressionHandler(expressionHandler);
		assertThat(manager).extracting("registry").extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		assertThatIllegalArgumentException().isThrownBy(() -> manager.setExpressionHandler(null))
				.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void checkDoSomethingWhenNoPostAuthorizeAnnotationThenNullDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething", new Class[] {}, new Object[] {});
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNull();
	}

	@Test
	public void checkDoSomethingStringWhenArgIsGrantThenGrantedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "grant" });
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkDoSomethingStringWhenArgIsNotGrantThenDeniedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "deny" });
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkRequiresAdminWhenClassAnnotationsThenMethodAnnotationsTakePrecedence() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "securedAdmin");
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, methodInvocation);
		assertThat(decision.isGranted()).isFalse();
		authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_ADMIN");
		decision = manager.check(authentication, methodInvocation);
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkRequiresUserWhenClassAnnotationsThenApplies() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "securedUser");
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, methodInvocation);
		assertThat(decision.isGranted()).isTrue();
		authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_ADMIN");
		decision = manager.check(authentication, methodInvocation);
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkInheritedAnnotationsWhenDuplicatedThenAnnotationConfigurationException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"inheritedAnnotations");
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> manager.check(authentication, methodInvocation));
	}

	@Test
	public void checkInheritedAnnotationsWhenConflictingThenAnnotationConfigurationException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "inheritedAnnotations");
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> manager.check(authentication, methodInvocation));
	}

	@Test
	public void checkTargetClassAwareWhenInterfaceLevelAnnotationsThenApplies() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestTargetClassAware(),
				TestTargetClassAware.class, "doSomething");
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
		decision = manager.check(TestAuthentication::authenticatedAdmin, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	public static class TestClass implements InterfaceAnnotationsOne, InterfaceAnnotationsTwo {

		public void doSomething() {

		}

		@PreAuthorize("#s == 'grant'")
		public String doSomethingString(String s) {
			return s;
		}

		@Override
		public void inheritedAnnotations() {

		}

	}

	@PreAuthorize("hasRole('USER')")
	public static class ClassLevelAnnotations implements InterfaceAnnotationsThree {

		@PreAuthorize("hasRole('ADMIN')")
		public void securedAdmin() {

		}

		public void securedUser() {

		}

		@Override
		@PreAuthorize("hasRole('ADMIN')")
		public void inheritedAnnotations() {

		}

	}

	public interface InterfaceAnnotationsOne {

		@PreAuthorize("hasRole('ADMIN')")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsTwo {

		@PreAuthorize("hasRole('USER')")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsThree {

		@MyPreAuthorize
		void inheritedAnnotations();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("hasRole('USER')")
	public @interface MyPreAuthorize {

	}

	@PreAuthorize("hasRole('ADMIN')")
	public interface InterfaceLevelAnnotations {

	}

	public static class TestTargetClassAware extends TestClass implements TargetClassAware, InterfaceLevelAnnotations {

		@Override
		public Class<?> getTargetClass() {
			return TestClass.class;
		}

		@Override
		public void doSomething() {
			super.doSomething();
		}

		@Override
		public String doSomethingString(String s) {
			return super.doSomethingString(s);
		}

		@Override
		public void inheritedAnnotations() {
			super.inheritedAnnotations();
		}

	}

}
