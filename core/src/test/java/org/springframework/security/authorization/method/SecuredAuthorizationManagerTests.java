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

import java.util.function.Supplier;

import org.junit.Test;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

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
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(methodInvocation,
				TestClass.class);
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser,
				methodAuthorizationContext);
		assertThat(decision).isNull();
	}

	@Test
	public void checkSecuredUserOrAdminWhenRoleUserThenGrantedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(methodInvocation,
				TestClass.class);
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser,
				methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkSecuredUserOrAdminWhenRoleAdminThenGrantedDecision() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(methodInvocation,
				TestClass.class);
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedAdmin,
				methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	public void checkSecuredUserOrAdminWhenRoleAnonymousThenDeniedDecision() throws Exception {
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password",
				"ROLE_ANONYMOUS");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"securedUserOrAdmin");
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(methodInvocation,
				TestClass.class);
		SecuredAuthorizationManager manager = new SecuredAuthorizationManager();
		AuthorizationDecision decision = manager.check(authentication, methodAuthorizationContext);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	public static class TestClass {

		public void doSomething() {

		}

		@Secured({ "ROLE_USER", "ROLE_ADMIN" })
		public void securedUserOrAdmin() {

		}

	}

}
