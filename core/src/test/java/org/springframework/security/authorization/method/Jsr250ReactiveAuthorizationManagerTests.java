/*
 * Copyright 2004-present the original author or authors.
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
import java.util.Collection;
import java.util.Set;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link Jsr250ReactiveAuthorizationManager}.
 *
 * @author Rohit Behera
 */
public class Jsr250ReactiveAuthorizationManagerTests {

	private final Jsr250ReactiveAuthorizationManager manager = new Jsr250ReactiveAuthorizationManager();

	@Test
	public void setRolePrefixWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.manager.setRolePrefix(null))
			.withMessage("rolePrefix cannot be null");
	}

	@Test
	public void setAuthoritiesAuthorizationManagerWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.manager.setAuthoritiesAuthorizationManager(null))
			.withMessage("authoritiesAuthorizationManager cannot be null");
	}

	@Test
	public void authorizeWhenNoJsr250AnnotationsThenEmpty() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething");
		StepVerifier.create(this.manager.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation))
			.verifyComplete();
	}

	@Test
	public void authorizeWhenPermitAllThenGranted() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class, "permitAll");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void authorizeWhenPermitAllAndNoAuthenticationThenGranted() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class, "permitAll");
		AuthorizationResult decision = this.manager.authorize(Mono.empty(), methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void authorizeWhenDenyAllAndRoleAdminThenDenied() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class, "denyAll");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedAdmin()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void authorizeWhenRolesAllowedUserOrAdminAndRoleUserThenGranted() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"rolesAllowedUserOrAdmin");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void authorizeWhenRolesAllowedUserOrAdminAndRoleAnonymousThenDenied() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"rolesAllowedUserOrAdmin");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.anonymousUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void authorizeWhenRolesAllowedAndNoAuthenticationThenDenied() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"rolesAllowedUserOrAdmin");
		AuthorizationResult decision = this.manager.authorize(Mono.empty(), methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void authorizeWhenRolesAllowedAndCustomRolePrefixThenUsesPrefix() throws Exception {
		this.manager.setRolePrefix("CUSTOM_");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"rolesAllowedAdmin");
		Mono<Authentication> customAdmin = Mono
			.just(new TestingAuthenticationToken("user", "password", "CUSTOM_ADMIN"));
		AuthorizationResult decision = this.manager.authorize(customAdmin, methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
		decision = this.manager.authorize(Mono.just(TestAuthentication.authenticatedAdmin()), methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void authorizeWhenCustomAuthoritiesAuthorizationManagerThenUsesIt() throws Exception {
		AuthorizationManager<Collection<String>> authoritiesAuthorizationManager = mock(AuthorizationManager.class);
		given(authoritiesAuthorizationManager.authorize(any(), eq(Set.of("ROLE_ADMIN"))))
			.willReturn(new AuthorizationDecision(true));
		this.manager.setAuthoritiesAuthorizationManager(authoritiesAuthorizationManager);
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"rolesAllowedAdmin");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void authorizeWhenClassLevelRolesAllowedThenAppliesToMethod() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "rolesAllowedClassLevel");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
		decision = this.manager.authorize(Mono.just(TestAuthentication.anonymousUser()), methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void authorizeWhenMethodLevelOverridesClassLevelThenUsesMethodLevel() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "rolesAllowedAdmin");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void authorizeWhenMultipleJsr250AnnotationsThenErrors() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"multipleAnnotations");
		StepVerifier.create(this.manager.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation))
			.expectError(AnnotationConfigurationException.class)
			.verify();
	}

	@Test
	public void authorizeWhenInheritedAnnotationThenGranted() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new RolesAllowedUserImpl(),
				RolesAllowedUserImpl.class, "doSomething");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	public static class TestClass {

		public void doSomething() {

		}

		@DenyAll
		public void denyAll() {

		}

		@PermitAll
		public void permitAll() {

		}

		@RolesAllowed("ADMIN")
		public void rolesAllowedAdmin() {

		}

		@RolesAllowed({ "USER", "ADMIN" })
		public void rolesAllowedUserOrAdmin() {

		}

		@RolesAllowed("USER")
		@DenyAll
		public void multipleAnnotations() {

		}

	}

	@RolesAllowed("USER")
	public static class ClassLevelAnnotations {

		public void rolesAllowedClassLevel() {

		}

		@RolesAllowed("ADMIN")
		public void rolesAllowedAdmin() {

		}

	}

	@Retention(RetentionPolicy.RUNTIME)
	@RolesAllowed("USER")
	public @interface MyRolesAllowedUser {

	}

	public interface RolesAllowedUserInterface {

		@MyRolesAllowedUser
		void doSomething();

	}

	public static class RolesAllowedUserImpl implements RolesAllowedUserInterface {

		@Override
		public void doSomething() {

		}

	}

}
