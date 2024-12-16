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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PostAuthorizeReactiveAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public class PostAuthorizeReactiveAuthorizationManagerTests {

	@Test
	public void setExpressionHandlerWhenNotNullThenSetsExpressionHandler() {
		MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		PostAuthorizeReactiveAuthorizationManager manager = new PostAuthorizeReactiveAuthorizationManager(
				expressionHandler);
		assertThat(manager).extracting("registry").extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new PostAuthorizeReactiveAuthorizationManager(null))
			.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void checkDoSomethingWhenNoPostAuthorizeAnnotationThenNullDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething", new Class[] {}, new Object[] {});
		PostAuthorizeReactiveAuthorizationManager manager = new PostAuthorizeReactiveAuthorizationManager();
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		AuthorizationDecision decision = manager.check(ReactiveAuthenticationUtils.getAuthentication(), result).block();
		assertThat(decision).isNull();
	}

	@Test
	public void checkDoSomethingStringWhenArgIsGrantThenGrantedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "grant" });
		PostAuthorizeReactiveAuthorizationManager manager = new PostAuthorizeReactiveAuthorizationManager();
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		AuthorizationDecision decision = manager.check(ReactiveAuthenticationUtils.getAuthentication(), result).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkDoSomethingStringWhenArgIsNotGrantThenDeniedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "deny" });
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		PostAuthorizeReactiveAuthorizationManager manager = new PostAuthorizeReactiveAuthorizationManager();
		AuthorizationDecision decision = manager.check(ReactiveAuthenticationUtils.getAuthentication(), result).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkDoSomethingListWhenReturnObjectContainsGrantThenGrantedDecision() throws Exception {
		List<String> list = Arrays.asList("grant", "deny");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingList", new Class[] { List.class }, new Object[] { list });
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, list);
		PostAuthorizeReactiveAuthorizationManager manager = new PostAuthorizeReactiveAuthorizationManager();
		AuthorizationDecision decision = manager.check(ReactiveAuthenticationUtils.getAuthentication(), result).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkDoSomethingListWhenReturnObjectNotContainsGrantThenDeniedDecision() throws Exception {
		List<String> list = Collections.singletonList("deny");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingList", new Class[] { List.class }, new Object[] { list });
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, list);
		PostAuthorizeReactiveAuthorizationManager manager = new PostAuthorizeReactiveAuthorizationManager();
		AuthorizationDecision decision = manager.check(ReactiveAuthenticationUtils.getAuthentication(), result).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkRequiresAdminWhenClassAnnotationsThenMethodAnnotationsTakePrecedence() throws Exception {
		Mono<Authentication> authentication = Mono
			.just(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "securedAdmin");
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		PostAuthorizeReactiveAuthorizationManager manager = new PostAuthorizeReactiveAuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, result).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
		authentication = Mono.just(new TestingAuthenticationToken("user", "password", "ROLE_ADMIN"));
		decision = manager.check(authentication, result).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkRequiresUserWhenClassAnnotationsThenApplies() throws Exception {
		Mono<Authentication> authentication = Mono
			.just(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "securedUser");
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		PostAuthorizeReactiveAuthorizationManager manager = new PostAuthorizeReactiveAuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, result).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
		authentication = Mono.just(new TestingAuthenticationToken("user", "password", "ROLE_ADMIN"));
		decision = manager.check(authentication, result).block();
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkInheritedAnnotationsWhenConflictingThenAnnotationConfigurationException() throws Exception {
		Mono<Authentication> authentication = Mono
			.just(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ConflictingAnnotations(),
				ConflictingAnnotations.class, "inheritedAnnotations");
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		PostAuthorizeReactiveAuthorizationManager manager = new PostAuthorizeReactiveAuthorizationManager();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> manager.check(authentication, result));
	}

	public static class TestClass implements InterfaceAnnotationsOne, InterfaceAnnotationsTwo {

		public void doSomething() {

		}

		@PostAuthorize("#s == 'grant'")
		public String doSomethingString(String s) {
			return s;
		}

		@PostAuthorize("returnObject.contains('grant')")
		public List<String> doSomethingList(List<String> list) {
			return list;
		}

		@Override
		public void inheritedAnnotations() {

		}

	}

	@PostAuthorize("hasRole('USER')")
	public static class ClassLevelAnnotations implements InterfaceAnnotationsThree {

		@PostAuthorize("hasRole('ADMIN')")
		public void securedAdmin() {

		}

		public void securedUser() {

		}

		@Override
		@PostAuthorize("hasRole('ADMIN')")
		public void inheritedAnnotations() {

		}

	}

	public static class ConflictingAnnotations implements InterfaceAnnotationsOne, InterfaceAnnotationsTwo {

		@Override
		public void inheritedAnnotations() {
		}

	}

	public interface InterfaceAnnotationsOne {

		@PostAuthorize("hasRole('ADMIN')")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsTwo {

		@PostAuthorize("hasRole('USER')")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsThree {

		@MyPostAuthorize
		void inheritedAnnotations();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PostAuthorize("hasRole('USER')")
	public @interface MyPostAuthorize {

	}

}
