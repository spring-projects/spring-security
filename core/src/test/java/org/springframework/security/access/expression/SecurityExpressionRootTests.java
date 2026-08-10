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

package org.springframework.security.access.expression;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.SingleResultAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Luke Taylor
 * @since 3.0
 */
public class SecurityExpressionRootTests {

	static final Authentication JOE = new TestingAuthenticationToken("joe", "pass", "ROLE_A", "ROLE_B");

	SecurityExpressionRoot root;

	@BeforeEach
	public void setup() {
		this.root = new SecurityExpressionRoot(JOE) {
		};
	}

	@Test
	public void denyAllIsFalsePermitAllTrue() {
		assertThat(this.root.denyAll()).isFalse();
		assertThat(this.root.denyAll).isFalse();
		assertThat(this.root.permitAll()).isTrue();
		assertThat(this.root.permitAll).isTrue();
	}

	@Test
	public void rememberMeIsCorrectlyDetected() {
		AuthenticationTrustResolver atr = mock(AuthenticationTrustResolver.class);
		this.root.setTrustResolver(atr);
		given(atr.isRememberMe(JOE)).willReturn(true);
		assertThat(this.root.isRememberMe()).isTrue();
		assertThat(this.root.isFullyAuthenticated()).isFalse();
	}

	@Test
	public void roleHierarchySupportIsCorrectlyUsedInEvaluatingRoles() {
		this.root.setRoleHierarchy((authorities) -> AuthorityUtils.createAuthorityList("ROLE_C"));
		assertThat(this.root.hasRole("C")).isTrue();
		assertThat(this.root.hasAuthority("ROLE_C")).isTrue();
		assertThat(this.root.hasRole("A")).isFalse();
		assertThat(this.root.hasRole("B")).isFalse();
		assertThat(this.root.hasAnyRole("C", "A", "B")).isTrue();
		assertThat(this.root.hasAnyAuthority("ROLE_C", "ROLE_A", "ROLE_B")).isTrue();
		assertThat(this.root.hasAnyRole("A", "B")).isFalse();
	}

	@Test
	public void hasRoleAddsDefaultPrefix() {
		assertThat(this.root.hasRole("A")).isTrue();
		assertThat(this.root.hasRole("NO")).isFalse();
	}

	@Test
	public void hasRoleEmptyPrefixDoesNotAddsDefaultPrefix() {
		this.root.setDefaultRolePrefix("");
		assertThat(this.root.hasRole("A")).isFalse();
		assertThat(this.root.hasRole("ROLE_A")).isTrue();
	}

	@Test
	public void hasRoleNullPrefixDoesNotAddsDefaultPrefix() {
		this.root.setDefaultRolePrefix(null);
		assertThat(this.root.hasRole("A")).isFalse();
		assertThat(this.root.hasRole("ROLE_A")).isTrue();
	}

	@Test
	public void hasRoleDoesNotAddDefaultPrefixForAlreadyPrefixedRoles() {
		SecurityExpressionRoot root = new SecurityExpressionRoot(JOE) {
		};
		assertThat(root.hasRole("ROLE_A")).isTrue();
		assertThat(root.hasRole("ROLE_NO")).isFalse();
	}

	@Test
	public void hasAnyRoleAddsDefaultPrefix() {
		assertThat(this.root.hasAnyRole("NO", "A")).isTrue();
		assertThat(this.root.hasAnyRole("NO", "NOT")).isFalse();
	}

	@Test
	public void hasAnyRoleDoesNotAddDefaultPrefixForAlreadyPrefixedRoles() {
		assertThat(this.root.hasAnyRole("ROLE_NO", "ROLE_A")).isTrue();
		assertThat(this.root.hasAnyRole("ROLE_NO", "ROLE_NOT")).isFalse();
	}

	@Test
	public void hasAnyRoleEmptyPrefixDoesNotAddsDefaultPrefix() {
		this.root.setDefaultRolePrefix("");
		assertThat(this.root.hasRole("A")).isFalse();
		assertThat(this.root.hasRole("ROLE_A")).isTrue();
	}

	@Test
	public void hasAnyRoleNullPrefixDoesNotAddsDefaultPrefix() {
		this.root.setDefaultRolePrefix(null);
		assertThat(this.root.hasAnyRole("A")).isFalse();
		assertThat(this.root.hasAnyRole("ROLE_A")).isTrue();
	}

	@Test
	public void hasAllRoles() {
		assertThat(this.root.hasAllRoles("A")).isTrue();
		assertThat(this.root.hasAllRoles("A", "B")).isTrue();
		assertThat(this.root.hasAllRoles("NO")).isFalse();
		assertThat(this.root.hasAllRoles("A", "NO")).isFalse();
	}

	@Test
	public void hasAuthorityDoesNotAddDefaultPrefix() {
		assertThat(this.root.hasAuthority("A")).isFalse();
		assertThat(this.root.hasAnyAuthority("NO", "A")).isFalse();
		assertThat(this.root.hasAnyAuthority("ROLE_A", "NOT")).isTrue();
	}

	@Test
	public void hasAllAuthorities() {
		assertThat(this.root.hasAllAuthorities("ROLE_A")).isTrue();
		assertThat(this.root.hasAllAuthorities("ROLE_A", "ROLE_B")).isTrue();
		assertThat(this.root.hasAllAuthorities("ROLE_NO")).isFalse();
		assertThat(this.root.hasAllAuthorities("ROLE_A", "ROLE_NO")).isFalse();
	}

	@Test
	void isAuthenticatedWhenAuthenticatedNullThenException() {
		this.root = new SecurityExpressionRoot((Authentication) null) {
		};
		assertThatIllegalArgumentException().isThrownBy(() -> this.root.isAuthenticated());
	}

	@Test
	void isAuthenticatedWhenTrustResolverFalseThenFalse() {
		AuthenticationTrustResolver atr = mock(AuthenticationTrustResolver.class);
		given(atr.isAuthenticated(JOE)).willReturn(false);
		this.root.setTrustResolver(atr);
		assertThat(this.root.isAuthenticated()).isFalse();
	}

	@Test
	void isAuthenticatedWhenTrustResolverTrueThenTrue() {
		AuthenticationTrustResolver atr = mock(AuthenticationTrustResolver.class);
		given(atr.isAuthenticated(JOE)).willReturn(true);
		this.root.setTrustResolver(atr);
		assertThat(this.root.isAuthenticated()).isTrue();
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void hasAuthorityDelegatesToAuthorizationManagerFactoryHasAuthority() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.hasAuthority("CUSTOM_AUTHORITY")).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.hasAuthority("CUSTOM_AUTHORITY")).isFalse();
		verify(factory).hasAuthority("CUSTOM_AUTHORITY");
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void hasAnyAuthorityDelegatesToAuthorizationManagerFactoryHasAnyAuthority() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.hasAnyAuthority("CUSTOM_AUTHORITY")).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.hasAnyAuthority("CUSTOM_AUTHORITY")).isFalse();
		verify(factory).hasAnyAuthority("CUSTOM_AUTHORITY");
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void hasAllAuthoritiesDelegatesToAuthorizationManagerFactoryHasAllAuthorities() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.hasAllAuthorities("A", "B")).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.hasAllAuthorities("A", "B")).isFalse();
		verify(factory).hasAllAuthorities("A", "B");
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void hasRoleDelegatesToAuthorizationManagerFactoryHasRole() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.hasRole("CUSTOM_ROLE")).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.hasRole("CUSTOM_ROLE")).isFalse();
		verify(factory).hasRole("CUSTOM_ROLE");
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void hasAnyRoleDelegatesToAuthorizationManagerFactoryHasAnyRole() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.hasAnyRole("A", "B")).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.hasAnyRole("A", "B")).isFalse();
		verify(factory).hasAnyRole("A", "B");
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void hasAllRolesDelegatesToAuthorizationManagerFactoryHasAllRoles() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.hasAllRoles("A", "B")).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.hasAllRoles("A", "B")).isFalse();
		verify(factory).hasAllRoles("A", "B");
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void permitAllDelegatesToAuthorizationManagerFactoryPermitAll() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.permitAll()).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.permitAll()).isFalse();
		verify(factory).permitAll();
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void denyAllDelegatesToAuthorizationManagerFactoryDenyAll() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.denyAll()).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.denyAll()).isFalse();
		verify(factory).denyAll();
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void isAnonymousDelegatesToAuthorizationManagerFactoryAnonymous() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.anonymous()).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.isAnonymous()).isFalse();
		verify(factory).anonymous();
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void isAuthenticatedDelegatesToAuthorizationManagerFactoryAuthenticated() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.authenticated()).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.isAuthenticated()).isFalse();
		verify(factory).authenticated();
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void isRememberMeDelegatesToAuthorizationManagerFactoryRememberMe() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.rememberMe()).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.isRememberMe()).isFalse();
		verify(factory).rememberMe();
	}

	// gh-18486
	@Test
	@SuppressWarnings("unchecked")
	public void isFullyAuthenticatedDelegatesToAuthorizationManagerFactoryFullyAuthenticated() {
		AuthorizationManagerFactory<Object> factory = mock(AuthorizationManagerFactory.class);
		AuthorizationManager<Object> manager = SingleResultAuthorizationManager.denyAll();
		given(factory.fullyAuthenticated()).willReturn(manager);
		this.root.setAuthorizationManagerFactory(factory);
		assertThat(this.root.isFullyAuthenticated()).isFalse();
		verify(factory).fullyAuthenticated();
	}

}
