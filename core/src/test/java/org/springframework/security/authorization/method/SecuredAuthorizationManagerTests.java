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

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.function.Supplier;

import org.junit.Test;

import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link SecuredAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public class SecuredAuthorizationManagerTests {

	@Test
	public void checkDoSomethingWhenNoSecuredAnnotationThenNullDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething");
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNull();
	}

	@Test
	public void checkSecuredUserOrAdminWhenRoleUserThenGrantedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkSecuredUserOrAdminWhenRoleAdminThenGrantedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedAdmin, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkSecuredUserOrAdminWhenRoleAnonymousThenDeniedDecision() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password",
				"ROLE_ANONYMOUS");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkRequiresAdminWhenClassAnnotationsThenMethodAnnotationsTakePrecedence() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "securedAdmin");
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
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
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
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
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> manager.check(authentication, methodInvocation));
	}

	@Test
	public void checkInheritedAnnotationsWhenConflictingThenAnnotationConfigurationException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "inheritedAnnotations");
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> manager.check(authentication, methodInvocation));
	}

	public static class TestClass implements InterfaceAnnotationsOne, InterfaceAnnotationsTwo {

		public void doSomething() {

		}

		@Secured({ "ROLE_USER", "ROLE_ADMIN" })
		public void securedUserOrAdmin() {

		}

		@Override
		public void inheritedAnnotations() {

		}

	}

	@Secured("ROLE_USER")
	public static class ClassLevelAnnotations implements InterfaceAnnotationsThree {

		@Secured("ROLE_ADMIN")
		public void securedAdmin() {

		}

		public void securedUser() {

		}

		@Override
		@Secured("ROLE_ADMIN")
		public void inheritedAnnotations() {

		}

	}

	public interface InterfaceAnnotationsOne {

		@Secured("ROLE_ADMIN")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsTwo {

		@Secured("ROLE_USER")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsThree {

		@MySecured
		void inheritedAnnotations();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@Secured("ROLE_USER")
	public @interface MySecured {

	}

}
