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

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PreAuthorizeReactiveAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public class PreAuthorizeReactiveAuthorizationManagerTests {

	@Test
	public void setExpressionHandlerWhenNotNullThenSetsExpressionHandler() {
		MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		PreAuthorizeReactiveAuthorizationManager manager = new PreAuthorizeReactiveAuthorizationManager(
				expressionHandler);
		assertThat(manager).extracting("registry").extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new PreAuthorizeReactiveAuthorizationManager(null))
				.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void checkDoSomethingWhenNoPostAuthorizeAnnotationThenNullDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething", new Class[] {}, new Object[] {});
		PreAuthorizeReactiveAuthorizationManager manager = new PreAuthorizeReactiveAuthorizationManager();
		AuthorizationDecision decision = manager
				.check(ReactiveAuthenticationUtils.getAuthentication(), methodInvocation).block();
		assertThat(decision).isNull();
	}

	@Test
	public void checkDoSomethingStringWhenArgIsGrantThenGrantedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "grant" });
		PreAuthorizeReactiveAuthorizationManager manager = new PreAuthorizeReactiveAuthorizationManager();
		AuthorizationDecision decision = manager
				.check(ReactiveAuthenticationUtils.getAuthentication(), methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkDoSomethingStringWhenArgIsNotGrantThenDeniedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "deny" });
		PreAuthorizeReactiveAuthorizationManager manager = new PreAuthorizeReactiveAuthorizationManager();
		AuthorizationDecision decision = manager
				.check(ReactiveAuthenticationUtils.getAuthentication(), methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkRequiresAdminWhenClassAnnotationsThenMethodAnnotationsTakePrecedence() throws Exception {
		Mono<Authentication> authentication = Mono
				.just(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "securedAdmin");
		PreAuthorizeReactiveAuthorizationManager manager = new PreAuthorizeReactiveAuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
		authentication = Mono.just(new TestingAuthenticationToken("user", "password", "ROLE_ADMIN"));
		decision = manager.check(authentication, methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkRequiresUserWhenClassAnnotationsThenApplies() throws Exception {
		Mono<Authentication> authentication = Mono
				.just(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "securedUser");
		PreAuthorizeReactiveAuthorizationManager manager = new PreAuthorizeReactiveAuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
		authentication = Mono.just(new TestingAuthenticationToken("user", "password", "ROLE_ADMIN"));
		decision = manager.check(authentication, methodInvocation).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkInheritedAnnotationsWhenDuplicatedThenAnnotationConfigurationException() throws Exception {
		Mono<Authentication> authentication = Mono
				.just(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"inheritedAnnotations");
		PreAuthorizeReactiveAuthorizationManager manager = new PreAuthorizeReactiveAuthorizationManager();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> manager.check(authentication, methodInvocation));
	}

	@Test
	public void checkInheritedAnnotationsWhenConflictingThenAnnotationConfigurationException() throws Exception {
		Mono<Authentication> authentication = Mono
				.just(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "inheritedAnnotations");
		PreAuthorizeReactiveAuthorizationManager manager = new PreAuthorizeReactiveAuthorizationManager();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> manager.check(authentication, methodInvocation));
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

}
