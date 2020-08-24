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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * @author Luke Taylor
 * @since 3.0
 */
public class SecurityExpressionRootTests {

	static final Authentication JOE = new TestingAuthenticationToken("joe", "pass", "ROLE_A", "ROLE_B");

	SecurityExpressionRoot root;

	@Before
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
	public void hasAuthorityDoesNotAddDefaultPrefix() {
		assertThat(this.root.hasAuthority("A")).isFalse();
		assertThat(this.root.hasAnyAuthority("NO", "A")).isFalse();
		assertThat(this.root.hasAnyAuthority("ROLE_A", "NOT")).isTrue();
	}

}
