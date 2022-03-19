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

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.junit.jupiter.api.Test;

import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link Jsr250AuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public class Jsr250AuthorizationManagerTests {

	@Test
	public void rolePrefixWhenNotSetThenDefaultsToRole() {
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		assertThat(manager).extracting("rolePrefix").isEqualTo("ROLE_");
	}

	@Test
	public void setRolePrefixWhenNullThenException() {
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		assertThatIllegalArgumentException().isThrownBy(() -> manager.setRolePrefix(null))
				.withMessage("rolePrefix cannot be null");
	}

	@Test
	public void setRolePrefixWhenNotNullThenSets() {
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		manager.setRolePrefix("CUSTOM_");
		assertThat(manager).extracting("rolePrefix").isEqualTo("CUSTOM_");
	}

	@Test
	public void checkDoSomethingWhenNoJsr250AnnotationsThenNullDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething");
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNull();
	}

	@Test
	public void checkPermitAllWhenRoleUserThenGrantedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class, "permitAll");
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkDenyAllWhenRoleAdminThenDeniedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class, "denyAll");
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedAdmin, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkRolesAllowedUserOrAdminWhenRoleUserThenGrantedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"rolesAllowedUserOrAdmin");
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkRolesAllowedUserOrAdminWhenRoleAdminThenGrantedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"rolesAllowedUserOrAdmin");
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedAdmin, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkRolesAllowedUserOrAdminWhenRoleAnonymousThenDeniedDecision() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password",
				"ROLE_ANONYMOUS");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"rolesAllowedUserOrAdmin");
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkMultipleAnnotationsWhenInvokedThenAnnotationConfigurationException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password",
				"ROLE_ANONYMOUS");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"multipleAnnotations");
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> manager.check(authentication, methodInvocation));
	}

	@Test
	public void checkRequiresAdminWhenClassAnnotationsThenMethodAnnotationsTakePrecedence() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "rolesAllowedAdmin");
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, methodInvocation);
		assertThat(decision.isGranted()).isFalse();
		authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_ADMIN");
		decision = manager.check(authentication, methodInvocation);
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkDeniedWhenClassAnnotationsThenMethodAnnotationsTakePrecedence() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "denyAll");
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, methodInvocation);
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkRequiresUserWhenClassAnnotationsThenApplies() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "rolesAllowedUser");
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
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
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> manager.check(authentication, methodInvocation));
	}

	@Test
	public void checkInheritedAnnotationsWhenConflictingThenAnnotationConfigurationException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "inheritedAnnotations");
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> manager.check(authentication, methodInvocation));
	}

	public static class TestClass implements InterfaceAnnotationsOne, InterfaceAnnotationsTwo {

		public void doSomething() {

		}

		@DenyAll
		public void denyAll() {

		}

		@PermitAll
		public void permitAll() {

		}

		@RolesAllowed({ "USER", "ADMIN" })
		public void rolesAllowedUserOrAdmin() {

		}

		@RolesAllowed("USER")
		@DenyAll
		public void multipleAnnotations() {

		}

		public void inheritedAnnotations() {

		}

	}

	@RolesAllowed("USER")
	public static class ClassLevelAnnotations implements InterfaceAnnotationsThree {

		@RolesAllowed("ADMIN")
		public void rolesAllowedAdmin() {

		}

		@DenyAll
		public void denyAll() {

		}

		public void rolesAllowedUser() {

		}

		@Override
		@PermitAll
		public void inheritedAnnotations() {

		}

	}

	public interface InterfaceAnnotationsOne {

		@RolesAllowed("ADMIN")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsTwo {

		@MyRolesAllowed
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsThree {

		@DenyAll
		void inheritedAnnotations();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@RolesAllowed("USER")
	public @interface MyRolesAllowed {

	}

}
