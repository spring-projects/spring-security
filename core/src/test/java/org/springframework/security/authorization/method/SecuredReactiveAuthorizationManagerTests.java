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

import java.util.Collection;
import java.util.Set;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link SecuredReactiveAuthorizationManager}.
 *
 * @author Rohit Behera
 */
public class SecuredReactiveAuthorizationManagerTests {

	private final SecuredReactiveAuthorizationManager manager = new SecuredReactiveAuthorizationManager();

	@Test
	public void setAuthoritiesAuthorizationManagerWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.manager.setAuthoritiesAuthorizationManager(null))
			.withMessage("authoritiesAuthorizationManager cannot be null");
	}

	@Test
	public void authorizeWhenNoSecuredAnnotationThenEmpty() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething");
		StepVerifier.create(this.manager.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation))
			.verifyComplete();
	}

	@Test
	public void authorizeWhenSecuredUserAndRoleUserThenGranted() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void authorizeWhenSecuredAdminAndRoleUserThenDenied() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedAdmin");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void authorizeWhenSecuredAndRoleAnonymousThenDenied() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.anonymousUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void authorizeWhenSecuredAndNoAuthenticationThenDenied() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		AuthorizationResult decision = this.manager.authorize(Mono.empty(), methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void authorizeWhenClassLevelSecuredThenAppliesToMethod() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "securedClassLevel");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void authorizeWhenMethodLevelOverridesClassLevelThenUsesMethodLevel() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "securedAdmin");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation)
			.block();
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
				"securedAdmin");
		AuthorizationResult decision = this.manager
			.authorize(Mono.just(TestAuthentication.authenticatedUser()), methodInvocation)
			.block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	public static class TestClass {

		public void doSomething() {

		}

		@Secured("ROLE_ADMIN")
		public void securedAdmin() {

		}

		@Secured({ "ROLE_USER", "ROLE_ADMIN" })
		public void securedUserOrAdmin() {

		}

	}

	@Secured("ROLE_USER")
	public static class ClassLevelAnnotations {

		public void securedClassLevel() {

		}

		@Secured("ROLE_ADMIN")
		public void securedAdmin() {

		}

	}

}
