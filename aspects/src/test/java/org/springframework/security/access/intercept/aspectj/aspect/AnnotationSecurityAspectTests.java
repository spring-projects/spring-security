/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.access.intercept.aspectj.aspect;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.ExpressionBasedPostInvocationAdvice;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.intercept.AfterInvocationProviderManager;
import org.springframework.security.access.intercept.aspectj.AspectJMethodSecurityInterceptor;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PostInvocationAdviceProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Luke Taylor
 * @since 3.0.3
 */
public class AnnotationSecurityAspectTests {

	private AffirmativeBased adm;

	@Mock
	private AuthenticationManager authman;

	private TestingAuthenticationToken anne = new TestingAuthenticationToken("anne", "", "ROLE_A");

	// private TestingAuthenticationToken bob = new TestingAuthenticationToken("bob", "",
	// "ROLE_B");
	private AspectJMethodSecurityInterceptor interceptor;

	private SecuredImpl secured = new SecuredImpl();

	private SecuredImplSubclass securedSub = new SecuredImplSubclass();

	private PrePostSecured prePostSecured = new PrePostSecured();

	@Before
	public final void setUp() {
		MockitoAnnotations.initMocks(this);
		this.interceptor = new AspectJMethodSecurityInterceptor();
		AccessDecisionVoter[] voters = new AccessDecisionVoter[] { new RoleVoter(),
				new PreInvocationAuthorizationAdviceVoter(new ExpressionBasedPreInvocationAdvice()) };
		this.adm = new AffirmativeBased(Arrays.<AccessDecisionVoter<? extends Object>>asList(voters));
		this.interceptor.setAccessDecisionManager(this.adm);
		this.interceptor.setAuthenticationManager(this.authman);
		this.interceptor.setSecurityMetadataSource(new SecuredAnnotationSecurityMetadataSource());
		AnnotationSecurityAspect secAspect = AnnotationSecurityAspect.aspectOf();
		secAspect.setSecurityInterceptor(this.interceptor);
	}

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void securedInterfaceMethodAllowsAllAccess() {
		this.secured.securedMethod();
	}

	@Test(expected = AuthenticationCredentialsNotFoundException.class)
	public void securedClassMethodDeniesUnauthenticatedAccess() {
		this.secured.securedClassMethod();
	}

	@Test
	public void securedClassMethodAllowsAccessToRoleA() {
		SecurityContextHolder.getContext().setAuthentication(this.anne);
		this.secured.securedClassMethod();
	}

	@Test(expected = AccessDeniedException.class)
	public void internalPrivateCallIsIntercepted() {
		SecurityContextHolder.getContext().setAuthentication(this.anne);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.secured.publicCallsPrivate());
		this.securedSub.publicCallsPrivate();
	}

	@Test(expected = AccessDeniedException.class)
	public void protectedMethodIsIntercepted() {
		SecurityContextHolder.getContext().setAuthentication(this.anne);
		this.secured.protectedMethod();
	}

	@Test
	public void overriddenProtectedMethodIsNotIntercepted() {
		// AspectJ doesn't inherit annotations
		this.securedSub.protectedMethod();
	}

	// SEC-1262
	@Test(expected = AccessDeniedException.class)
	public void denyAllPreAuthorizeDeniesAccess() {
		configureForElAnnotations();
		SecurityContextHolder.getContext().setAuthentication(this.anne);
		this.prePostSecured.denyAllMethod();
	}

	@Test
	public void postFilterIsApplied() {
		configureForElAnnotations();
		SecurityContextHolder.getContext().setAuthentication(this.anne);
		List<String> objects = this.prePostSecured.postFilterMethod();
		assertThat(objects).hasSize(2);
		assertThat(objects.contains("apple")).isTrue();
		assertThat(objects.contains("aubergine")).isTrue();
	}

	private void configureForElAnnotations() {
		DefaultMethodSecurityExpressionHandler eh = new DefaultMethodSecurityExpressionHandler();
		this.interceptor.setSecurityMetadataSource(
				new PrePostAnnotationSecurityMetadataSource(new ExpressionBasedAnnotationAttributeFactory(eh)));
		this.interceptor.setAccessDecisionManager(this.adm);
		AfterInvocationProviderManager aim = new AfterInvocationProviderManager();
		aim.setProviders(Arrays.asList(new PostInvocationAdviceProvider(new ExpressionBasedPostInvocationAdvice(eh))));
		this.interceptor.setAfterInvocationManager(aim);
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
		public void securedClassMethod() {
		}

		@Secured("ROLE_X")
		private void privateMethod() {
		}

		@Secured("ROLE_X")
		protected void protectedMethod() {
		}

		@Secured("ROLE_X")
		public void publicCallsPrivate() {
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

	static class PrePostSecured {

		@PreAuthorize("denyAll")
		public void denyAllMethod() {
		}

		@PostFilter("filterObject.startsWith('a')")
		public List<String> postFilterMethod() {
			ArrayList<String> objects = new ArrayList<>();
			objects.addAll(Arrays.asList(new String[] { "apple", "banana", "aubergine", "orange" }));
			return objects;
		}

	}

}
