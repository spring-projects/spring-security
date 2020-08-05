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
package org.springframework.security.access.expression;

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Luke Taylor
 * @since 3.0
 */
public class SecurityExpressionRootTests {

	final static Authentication JOE = new TestingAuthenticationToken("joe", "pass", "ROLE_A", "ROLE_B");

	SecurityExpressionRoot root;

	@Before
	public void setup() {
		root = new SecurityExpressionRoot(JOE) {
		};
	}

	@Test
	public void denyAllIsFalsePermitAllTrue() {
		assertThat(root.denyAll()).isFalse();
		assertThat(root.denyAll).isFalse();
		assertThat(root.permitAll()).isTrue();
		assertThat(root.permitAll).isTrue();
	}

	@Test
	public void rememberMeIsCorrectlyDetected() {
		AuthenticationTrustResolver atr = mock(AuthenticationTrustResolver.class);
		root.setTrustResolver(atr);
		when(atr.isRememberMe(JOE)).thenReturn(true);
		assertThat(root.isRememberMe()).isTrue();
		assertThat(root.isFullyAuthenticated()).isFalse();
	}

	@Test
	public void roleHierarchySupportIsCorrectlyUsedInEvaluatingRoles() {
		root.setRoleHierarchy(authorities -> AuthorityUtils.createAuthorityList("ROLE_C"));

		assertThat(root.hasRole("C")).isTrue();
		assertThat(root.hasAuthority("ROLE_C")).isTrue();
		assertThat(root.hasRole("A")).isFalse();
		assertThat(root.hasRole("B")).isFalse();
		assertThat(root.hasAnyRole("C", "A", "B")).isTrue();
		assertThat(root.hasAnyAuthority("ROLE_C", "ROLE_A", "ROLE_B")).isTrue();
		assertThat(root.hasAnyRole("A", "B")).isFalse();
	}

	@Test
	public void hasRoleAddsDefaultPrefix() {
		assertThat(root.hasRole("A")).isTrue();
		assertThat(root.hasRole("NO")).isFalse();
	}

	@Test
	public void hasRoleEmptyPrefixDoesNotAddsDefaultPrefix() {
		root.setDefaultRolePrefix("");
		assertThat(root.hasRole("A")).isFalse();
		assertThat(root.hasRole("ROLE_A")).isTrue();
	}

	@Test
	public void hasRoleNullPrefixDoesNotAddsDefaultPrefix() {
		root.setDefaultRolePrefix(null);
		assertThat(root.hasRole("A")).isFalse();
		assertThat(root.hasRole("ROLE_A")).isTrue();
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
		assertThat(root.hasAnyRole("NO", "A")).isTrue();
		assertThat(root.hasAnyRole("NO", "NOT")).isFalse();
	}

	@Test
	public void hasAnyRoleDoesNotAddDefaultPrefixForAlreadyPrefixedRoles() {
		assertThat(root.hasAnyRole("ROLE_NO", "ROLE_A")).isTrue();
		assertThat(root.hasAnyRole("ROLE_NO", "ROLE_NOT")).isFalse();
	}

	@Test
	public void hasAnyRoleEmptyPrefixDoesNotAddsDefaultPrefix() {
		root.setDefaultRolePrefix("");
		assertThat(root.hasRole("A")).isFalse();
		assertThat(root.hasRole("ROLE_A")).isTrue();
	}

	@Test
	public void hasAnyRoleNullPrefixDoesNotAddsDefaultPrefix() {
		root.setDefaultRolePrefix(null);
		assertThat(root.hasAnyRole("A")).isFalse();
		assertThat(root.hasAnyRole("ROLE_A")).isTrue();
	}

	@Test
	public void hasAuthorityDoesNotAddDefaultPrefix() {
		assertThat(root.hasAuthority("A")).isFalse();
		assertThat(root.hasAnyAuthority("NO", "A")).isFalse();
		assertThat(root.hasAnyAuthority("ROLE_A", "NOT")).isTrue();
	}

}
