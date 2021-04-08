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

import java.util.Collections;
import java.util.function.Supplier;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

import org.junit.Test;

import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
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
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething");
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNull();
	}

	@Test
	public void checkPermitAllRolesAllowedAdminWhenRoleUserThenGrantedDecision() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"permitAllRolesAllowedAdmin");
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkDenyAllRolesAllowedAdminWhenRoleAdminThenDeniedDecision() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"denyAllRolesAllowedAdmin");
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedAdmin, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkRolesAllowedUserOrAdminWhenRoleUserThenGrantedDecision() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"rolesAllowedUserOrAdmin");
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkRolesAllowedUserOrAdminWhenRoleAdminThenGrantedDecision() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"rolesAllowedUserOrAdmin");
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedAdmin, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkRolesAllowedUserOrAdminWhenRoleAnonymousThenDeniedDecision() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password",
				"ROLE_ANONYMOUS");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"rolesAllowedUserOrAdmin");
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, methodInvocation);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	public static class TestClass {

		public void doSomething() {

		}

		@DenyAll
		@RolesAllowed("ADMIN")
		public void denyAllRolesAllowedAdmin() {

		}

		@PermitAll
		@RolesAllowed("ADMIN")
		public void permitAllRolesAllowedAdmin() {

		}

		@RolesAllowed({ "USER", "ADMIN" })
		public void rolesAllowedUserOrAdmin() {

		}

	}

}
