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

package org.springframework.security.authorization.method.aspectj;

import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Luke Taylor
 * @since 3.0.3
 */
public class PostAuthorizeAspectTests {

	private TestingAuthenticationToken anne = new TestingAuthenticationToken("anne", "", "ROLE_A");

	private MethodInterceptor interceptor;

	private SecuredImpl secured = new SecuredImpl();

	private SecuredImplSubclass securedSub = new SecuredImplSubclass();

	private PrePostSecured prePostSecured = new PrePostSecured();

	@BeforeEach
	public final void setUp() {
		MockitoAnnotations.initMocks(this);
		this.interceptor = AuthorizationManagerAfterMethodInterceptor.postAuthorize();
		PostAuthorizeAspect secAspect = PostAuthorizeAspect.aspectOf();
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

	// SEC-1262
	@Test
	public void denyAllPreAuthorizeDeniesAccess() {
		SecurityContextHolder.getContext().setAuthentication(this.anne);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.prePostSecured::denyAllMethod);
	}

	@Test
	public void nestedDenyAllPostAuthorizeDeniesAccess() {
		SecurityContextHolder.getContext().setAuthentication(this.anne);
		assertThatExceptionOfType(AccessDeniedException.class)
			.isThrownBy(() -> this.secured.myObject().denyAllMethod());
	}

	interface SecuredInterface {

		@PostAuthorize("hasRole('X')")
		void securedMethod();

	}

	static class SecuredImpl implements SecuredInterface {

		// Not really secured because AspectJ doesn't inherit annotations from interfaces
		@Override
		public void securedMethod() {
		}

		@PostAuthorize("hasRole('A')")
		void securedClassMethod() {
		}

		@PostAuthorize("hasRole('X')")
		private void privateMethod() {
		}

		@PostAuthorize("hasRole('X')")
		protected void protectedMethod() {
		}

		@PostAuthorize("hasRole('X')")
		void publicCallsPrivate() {
			privateMethod();
		}

		NestedObject myObject() {
			return new NestedObject();
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

	static class PrePostSecured {

		@PostAuthorize("denyAll")
		void denyAllMethod() {
		}

	}

	static class NestedObject {

		@PostAuthorize("denyAll")
		void denyAllMethod() {

		}

	}

}
