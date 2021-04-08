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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authorization.AuthorizationDecision;

import static org.assertj.core.api.Assertions.assertThat;
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
		assertThat(manager).extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		assertThatIllegalArgumentException().isThrownBy(() -> manager.setExpressionHandler(null))
				.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void checkDoSomethingWhenNoPostAuthorizeAnnotationThenNullDecision() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething", new Class[] {}, new Object[] {});
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation, null);
		assertThat(decision).isNull();
	}

	@Test
	public void checkDoSomethingStringWhenArgIsGrantThenGrantedDecision() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "grant" });
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkDoSomethingStringWhenArgIsNotGrantThenDeniedDecision() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "deny" });
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	public void checkDoSomethingListWhenReturnObjectContainsGrantThenGrantedDecision() throws Exception {
		List<String> list = Arrays.asList("grant", "deny");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingList", new Class[] { List.class }, new Object[] { list });
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation, list);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkDoSomethingListWhenReturnObjectNotContainsGrantThenDeniedDecision() throws Exception {
		List<String> list = Collections.singletonList("deny");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingList", new Class[] { List.class }, new Object[] { list });
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser, methodInvocation, list);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	public static class TestClass {

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

	}

}
