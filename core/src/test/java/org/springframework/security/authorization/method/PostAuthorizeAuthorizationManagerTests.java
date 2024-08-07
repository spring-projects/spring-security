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

package org.springframework.security.authorization.method;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.Test;

import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PostAuthorizeAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public class PostAuthorizeAuthorizationManagerTests {

	@Test
	public void setExpressionHandlerWhenNotNullThenSetsExpressionHandler() {
		MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		manager.setExpressionHandler(expressionHandler);
		assertThat(manager).extracting("registry").extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		assertThatIllegalArgumentException().isThrownBy(() -> manager.setExpressionHandler(null))
			.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void checkDoSomethingWhenNoPostAuthorizeAnnotationThenNullDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething", new Class[] {}, new Object[] {});
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, result);
		assertThat(decision).isNull();
	}

	@Test
	public void checkDoSomethingStringWhenArgIsGrantThenGrantedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "grant" });
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, result);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkDoSomethingStringWhenArgIsNotGrantThenDeniedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "deny" });
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, result);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkDoSomethingListWhenReturnObjectContainsGrantThenGrantedDecision() throws Exception {
		List<String> list = Arrays.asList("grant", "deny");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingList", new Class[] { List.class }, new Object[] { list });
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, list);
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, result);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkDoSomethingListWhenReturnObjectNotContainsGrantThenDeniedDecision() throws Exception {
		List<String> list = Collections.singletonList("deny");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingList", new Class[] { List.class }, new Object[] { list });
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, list);
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, result);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkRequiresAdminWhenClassAnnotationsThenMethodAnnotationsTakePrecedence() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "securedAdmin");
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, result);
		assertThat(decision.isGranted()).isFalse();
		authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_ADMIN");
		decision = manager.check(authentication, result);
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkRequiresUserWhenClassAnnotationsThenApplies() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ClassLevelAnnotations(),
				ClassLevelAnnotations.class, "securedUser");
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, result);
		assertThat(decision.isGranted()).isTrue();
		authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_ADMIN");
		decision = manager.check(authentication, result);
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkInheritedAnnotationsWhenConflictingThenAnnotationConfigurationException() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ConflictingAnnotations(),
				ConflictingAnnotations.class, "inheritedAnnotations");
		MethodInvocationResult result = new MethodInvocationResult(methodInvocation, null);
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> manager.check(authentication, result));
	}

	@Test
	public void checkWhenHandlerDeniedNoApplicationContextThenReflectivelyConstructs() throws Exception {
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		assertThat(handleDeniedInvocationResult("methodOne", manager)).isNull();
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> handleDeniedInvocationResult("methodTwo", manager));
	}

	@Test
	public void checkWhenHandlerDeniedApplicationContextThenLooksForBean() throws Exception {
		GenericApplicationContext context = new GenericApplicationContext();
		context.registerBean(NoDefaultConstructorHandler.class, () -> new NoDefaultConstructorHandler(new Object()));
		context.refresh();
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		manager.setApplicationContext(context);
		assertThat(handleDeniedInvocationResult("methodTwo", manager)).isNull();
		assertThatExceptionOfType(IllegalStateException.class)
			.isThrownBy(() -> handleDeniedInvocationResult("methodOne", manager));
	}

	private Object handleDeniedInvocationResult(String methodName, PostAuthorizeAuthorizationManager manager)
			throws Exception {
		MethodInvocation invocation = new MockMethodInvocation(new UsingHandleDeniedAuthorization(),
				UsingHandleDeniedAuthorization.class, methodName);
		MethodInvocationResult result = new MethodInvocationResult(invocation, null);
		return manager.handleDeniedInvocationResult(result, null);
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

	public static final class UsingHandleDeniedAuthorization {

		@HandleAuthorizationDenied(handlerClass = NullHandler.class)
		@PostAuthorize("denyAll()")
		public String methodOne() {
			return "ok";
		}

		@HandleAuthorizationDenied(handlerClass = NoDefaultConstructorHandler.class)
		@PostAuthorize("denyAll()")
		public String methodTwo() {
			return "ok";
		}

	}

	public static final class NullHandler implements MethodAuthorizationDeniedHandler {

		@Override
		public Object handleDeniedInvocation(MethodInvocation methodInvocation,
				AuthorizationResult authorizationResult) {
			return null;
		}

	}

	public static final class NoDefaultConstructorHandler implements MethodAuthorizationDeniedHandler {

		private NoDefaultConstructorHandler(Object parameter) {

		}

		@Override
		public Object handleDeniedInvocation(MethodInvocation methodInvocation,
				AuthorizationResult authorizationResult) {
			return null;
		}

	}

}
