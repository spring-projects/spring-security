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

package org.springframework.security.authorization.method.aspectj;

import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Luke Taylor
 * @since 3.0.3
 */
public class SecuredAspectTests {

	private TestingAuthenticationToken anne = new TestingAuthenticationToken("anne", "", "ROLE_A");

	private MethodInterceptor interceptor;

	private SecuredImpl secured = new SecuredImpl();

	private SecuredImplSubclass securedSub = new SecuredImplSubclass();

	@BeforeEach
	public final void setUp() {
		MockitoAnnotations.initMocks(this);
		this.interceptor = AuthorizationManagerBeforeMethodInterceptor.secured();
		SecuredAspect secAspect = SecuredAspect.aspectOf();
		secAspect.setSecurityInterceptor(this.interceptor);
	}

	@AfterEach
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void securedInterfaceMethodAllowsAllAccess() {
		this.secured.securedMethod();
	}

	@Test
	public void securedClassMethodDeniesUnauthenticatedAccess() {
		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class)
				.isThrownBy(() -> this.secured.securedClassMethod());
	}

	@Test
	public void securedClassMethodAllowsAccessToRoleA() {
		SecurityContextHolder.getContext().setAuthentication(this.anne);
		this.secured.securedClassMethod();
	}

	@Test
	public void internalPrivateCallIsIntercepted() {
		SecurityContextHolder.getContext().setAuthentication(this.anne);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.secured.publicCallsPrivate());
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.securedSub.publicCallsPrivate());
	}

	@Test
	public void protectedMethodIsIntercepted() {
		SecurityContextHolder.getContext().setAuthentication(this.anne);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.secured.protectedMethod());
	}

	@Test
	public void overriddenProtectedMethodIsNotIntercepted() {
		// AspectJ doesn't inherit annotations
		this.securedSub.protectedMethod();
	}

	interface SecuredInterface {

		@Secured("ROLE_X")
		void securedMethod();

	}

	static class SecuredImpl implements SecuredInterface {

		// Not really secured because AspectJ doesn't inherit annotations from interfaces
		@Override
		public void securedMethod() {
		}

		@Secured("ROLE_A")
		void securedClassMethod() {
		}

		@Secured("ROLE_X")
		private void privateMethod() {
		}

		@Secured("ROLE_X")
		protected void protectedMethod() {
		}

		@Secured("ROLE_X")
		void publicCallsPrivate() {
			privateMethod();
		}

	}

	static class SecuredImplSubclass extends SecuredImpl {

		@Override
		protected void protectedMethod() {
		}

		@Override
		public void publicCallsPrivate() {
			super.publicCallsPrivate();
		}

	}

}
