/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.authentication;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests
 * {@link org.springframework.security.authentication.AuthenticationTrustResolverImpl}.
 *
 * @author Ben Alex
 */
public class AuthenticationTrustResolverImplTests {

	@Test
	public void testCorrectOperationIsAnonymous() {
		AuthenticationTrustResolverImpl trustResolver = new AuthenticationTrustResolverImpl();
		assertThat(trustResolver.isAnonymous(
				new AnonymousAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ignored"))))
			.isTrue();
		assertThat(trustResolver.isAnonymous(
				new TestingAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ignored"))))
			.isFalse();
	}

	@Test
	public void testCorrectOperationIsRememberMe() {
		AuthenticationTrustResolverImpl trustResolver = new AuthenticationTrustResolverImpl();
		assertThat(trustResolver.isRememberMe(
				new RememberMeAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ignored"))))
			.isTrue();
		assertThat(trustResolver.isAnonymous(
				new TestingAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ignored"))))
			.isFalse();
	}

	@Test
	public void testGettersSetters() {
		AuthenticationTrustResolverImpl trustResolver = new AuthenticationTrustResolverImpl();
		assertThat(AnonymousAuthenticationToken.class).isEqualTo(trustResolver.getAnonymousClass());
		trustResolver.setAnonymousClass(TestingAuthenticationToken.class);
		assertThat(trustResolver.getAnonymousClass()).isEqualTo(TestingAuthenticationToken.class);
		assertThat(RememberMeAuthenticationToken.class).isEqualTo(trustResolver.getRememberMeClass());
		trustResolver.setRememberMeClass(TestingAuthenticationToken.class);
		assertThat(trustResolver.getRememberMeClass()).isEqualTo(TestingAuthenticationToken.class);
	}

	@Test
	void isAuthenticatedWhenAuthenticationNullThenFalse() {
		AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
		Authentication authentication = null;
		assertThat(trustResolver.isAuthenticated(authentication)).isFalse();
	}

	@Test
	void isAuthenticatedWhenAuthenticationNotAuthenticatedThenFalse() {
		AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");
		assertThat(trustResolver.isAuthenticated(authentication)).isFalse();
	}

	@Test
	void isAuthenticatedWhenAnonymousThenFalse() {
		AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
		AnonymousAuthenticationToken authentication = new AnonymousAuthenticationToken("key", "principal",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		assertThat(trustResolver.isAuthenticated(authentication)).isFalse();
	}

	@Test
	void isFullyAuthenticatedWhenAuthenticationNullThenFalse() {
		AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
		Authentication authentication = null;
		assertThat(trustResolver.isFullyAuthenticated(authentication)).isFalse();
	}

	@Test
	void isFullyAuthenticatedWhenAuthenticationNotAuthenticatedThenFalse() {
		AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");
		assertThat(trustResolver.isFullyAuthenticated(authentication)).isFalse();
	}

	@Test
	void isFullyAuthenticatedWhenAnonymousThenFalse() {
		AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
		AnonymousAuthenticationToken authentication = new AnonymousAuthenticationToken("key", "principal",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		assertThat(trustResolver.isFullyAuthenticated(authentication)).isFalse();
	}

	@Test
	void isFullyAuthenticatedWhenRememberMeThenFalse() {
		AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
		RememberMeAuthenticationToken authentication = new RememberMeAuthenticationToken("key", "user",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		assertThat(trustResolver.isFullyAuthenticated(authentication)).isFalse();
	}

}
