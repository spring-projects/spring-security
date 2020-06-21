/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.access.hierarchicalroles;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests for {@link RoleHierarchyBuilder}.
 *
 * @author Sebastijan Grabar
 */
public class RoleHierarchyBuilderTests {

	private final String ROLE_0 = "ROLE_0";
	private final String ROLE_A = "ROLE_A";
	private final String ROLE_B = "ROLE_B";
	private final String ROLE_C = "ROLE_C";
	private final String ROLE_D = "ROLE_D";
	private final String ROLE_E = "ROLE_E";

	@Test
	public void testSimpleRoleHierarchy() {
		List<GrantedAuthority> authorities0 = AuthorityUtils.createAuthorityList(
				ROLE_0);
		List<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList(
				ROLE_A);
		List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList(ROLE_A,
				ROLE_B);

		RoleHierarchy roleHierarchy = RoleHierarchyBuilder
				.builder()
				.role(ROLE_A)
					.includes(ROLE_B)
					.build();

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy.getReachableGrantedAuthorities(authorities0),
				authorities0)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy.getReachableGrantedAuthorities(authorities1),
				authorities2)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy.getReachableGrantedAuthorities(authorities2),
				authorities2)).isTrue();
	}

	@Test
	public void testTransitiveRoleHierarchies() {
		List<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList(
				ROLE_A);
		List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList(ROLE_A,
				ROLE_B, ROLE_C);
		List<GrantedAuthority> authorities3 = AuthorityUtils.createAuthorityList(ROLE_A,
				ROLE_B, ROLE_C, ROLE_D);

		RoleHierarchy roleHierarchy1 = RoleHierarchyBuilder
				.builder()
				.role(ROLE_A)
				.includes(ROLE_B)
				.whichIncludes(ROLE_C)
				.build();

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy1.getReachableGrantedAuthorities(authorities1),
				authorities2)).isTrue();

		RoleHierarchy roleHierarchy2 = RoleHierarchyBuilder
				.builder()
				.role(ROLE_A)
					.includes(ROLE_B)
					.and()
				.role(ROLE_B)
					.includes(ROLE_C)
					.build();

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy2.getReachableGrantedAuthorities(authorities1),
				authorities2)).isTrue();

		RoleHierarchy roleHierarchy3 = RoleHierarchyBuilder
				.builder()
				.role(ROLE_A)
					.includes(ROLE_B)
					.whichIncludes(ROLE_C)
					.whichIncludes(ROLE_D)
					.build();

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy3.getReachableGrantedAuthorities(authorities1),
				authorities3)).isTrue();

		RoleHierarchy roleHierarchy4 = RoleHierarchyBuilder
				.builder()
				.role(ROLE_A)
					.includes(ROLE_B)
					.and()
				.role(ROLE_B)
					.includes(ROLE_C)
					.and()
				.role(ROLE_C)
					.includes(ROLE_D)
					.build();

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy4.getReachableGrantedAuthorities(authorities1),
				authorities3)).isTrue();
	}

	@Test
	public void testComplexRoleHierarchy() {
		List<GrantedAuthority> authoritiesInput1 = AuthorityUtils.createAuthorityList(
				ROLE_A);
		List<GrantedAuthority> authoritiesOutput1 = AuthorityUtils.createAuthorityList(
				ROLE_A, ROLE_B, ROLE_C, ROLE_D);
		List<GrantedAuthority> authoritiesInput2 = AuthorityUtils.createAuthorityList(
				ROLE_B);
		List<GrantedAuthority> authoritiesOutput2 = AuthorityUtils.createAuthorityList(
				ROLE_B, ROLE_D);
		List<GrantedAuthority> authoritiesInput3 = AuthorityUtils.createAuthorityList(
				ROLE_C);
		List<GrantedAuthority> authoritiesOutput3 = AuthorityUtils.createAuthorityList(
				ROLE_C, ROLE_D);
		List<GrantedAuthority> authoritiesInput4 = AuthorityUtils.createAuthorityList(
				ROLE_D);
		List<GrantedAuthority> authoritiesOutput4 = AuthorityUtils.createAuthorityList(
				ROLE_D);

		RoleHierarchy roleHierarchy = RoleHierarchyBuilder
				.builder()
				.role(ROLE_A)
					.includes(ROLE_B)
					.and()
				.role(ROLE_A)
					.includes(ROLE_C)
					.and()
				.role(ROLE_C)
					.includes(ROLE_D)
					.and()
				.role(ROLE_B)
					.includes(ROLE_D)
					.build();

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy.getReachableGrantedAuthorities(authoritiesInput1),
				authoritiesOutput1)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy.getReachableGrantedAuthorities(authoritiesInput2),
				authoritiesOutput2)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy.getReachableGrantedAuthorities(authoritiesInput3),
				authoritiesOutput3)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy.getReachableGrantedAuthorities(authoritiesInput4),
				authoritiesOutput4)).isTrue();

		RoleHierarchy roleHierarchy2 = RoleHierarchyBuilder
				.builder()
				.role(ROLE_A)
					.includes(ROLE_B)
					.whichIncludes(ROLE_D)
					.and()
				.role(ROLE_A)
					.includes(ROLE_C)
					.whichIncludes(ROLE_D)
					.build();

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy2.getReachableGrantedAuthorities(authoritiesInput1),
				authoritiesOutput1)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy2.getReachableGrantedAuthorities(authoritiesInput2),
				authoritiesOutput2)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy2.getReachableGrantedAuthorities(authoritiesInput3),
				authoritiesOutput3)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchy2.getReachableGrantedAuthorities(authoritiesInput4),
				authoritiesOutput4)).isTrue();
	}

	@Test
	public void testCyclesInRoleHierarchy() {
		try {
			RoleHierarchyBuilder
					.builder()
					.role(ROLE_A)
						.includes(ROLE_A)
						.build();
			fail("Cycle in role hierarchy was not detected!");
		} catch (CycleInRoleHierarchyException e) {
		}

		try {
			RoleHierarchyBuilder
					.builder()
					.role(ROLE_A)
						.includes(ROLE_B)
						.whichIncludes(ROLE_A)
						.build();
			fail("Cycle in role hierarchy was not detected!");
		} catch (CycleInRoleHierarchyException e) {
		}

		try {
			RoleHierarchyBuilder
					.builder()
						.role(ROLE_A)
						.includes(ROLE_B)
						.and()
					.role(ROLE_B)
						.includes(ROLE_A)
						.build();
			fail("Cycle in role hierarchy was not detected!");
		} catch (CycleInRoleHierarchyException e) {
		}

		try {
			RoleHierarchyBuilder
					.builder()
					.role(ROLE_A)
						.includes(ROLE_B)
						.whichIncludes(ROLE_C)
						.whichIncludes(ROLE_A)
						.build();
			fail("Cycle in role hierarchy was not detected!");
		} catch (CycleInRoleHierarchyException e) {
		}

		try {
			RoleHierarchyBuilder
					.builder()
					.role(ROLE_A)
						.includes(ROLE_B)
						.and()
					.role(ROLE_B)
						.includes(ROLE_C)
						.and()
					.role(ROLE_C)
						.includes(ROLE_A)
						.build();
			fail("Cycle in role hierarchy was not detected!");
		} catch (CycleInRoleHierarchyException e) {
		}

		try {
			RoleHierarchyBuilder
					.builder()
					.role(ROLE_A)
						.includes(ROLE_B)
						.whichIncludes(ROLE_C)
						.whichIncludes(ROLE_E)
						.whichIncludes(ROLE_D)
						.whichIncludes(ROLE_B)
						.build();

			fail("Cycle in role hierarchy was not detected!");
		} catch (CycleInRoleHierarchyException e) {
		}

		try {
			RoleHierarchyBuilder
					.builder()
					.role(ROLE_A)
						.includes(ROLE_B)
						.and()
					.role(ROLE_B)
						.includes(ROLE_C)
						.and()
					.role(ROLE_C)
						.includes(ROLE_E)
						.and()
					.role(ROLE_E)
						.includes(ROLE_D)
						.and()
					.role(ROLE_D)
						.includes(ROLE_B)
						.build();

			fail("Cycle in role hierarchy was not detected!");
		} catch (CycleInRoleHierarchyException e) {
		}

		try {
			RoleHierarchyBuilder
					.builder()
					.role(ROLE_C)
						.includes(ROLE_B)
						.whichIncludes(ROLE_A)
						.whichIncludes(ROLE_B)
						.build();
			fail("Cycle in role hierarchy was not detected!");
		} catch (CycleInRoleHierarchyException e) {
		}

		try {
			RoleHierarchyBuilder
					.builder()
					.role(ROLE_C)
						.includes(ROLE_B)
						.and()
					.role(ROLE_B)
						.includes(ROLE_A)
						.and()
					.role(ROLE_A)
						.includes(ROLE_B)
						.build();
			fail("Cycle in role hierarchy was not detected!");
		} catch (CycleInRoleHierarchyException e) {
		}
	}

	@Test
	public void testNoCyclesInRoleHierarchy() {
		try {
			RoleHierarchyBuilder
					.builder()
					.role(ROLE_A)
						.includes(ROLE_B)
						.whichIncludes(ROLE_D)
						.and()
					.role(ROLE_A)
						.includes(ROLE_C)
						.whichIncludes(ROLE_D)
						.build();

		} catch (CycleInRoleHierarchyException e) {
			fail("A cycle in role hierarchy was incorrectly detected!");
		}
	}

	// SEC-863
	@Test
	public void testSimpleRoleHierarchyWithCustomGrantedAuthorityImplementation() {
		List<GrantedAuthority> authorities0 = HierarchicalRolesTestHelper.createAuthorityList(
				ROLE_0);
		List<GrantedAuthority> authorities1 = HierarchicalRolesTestHelper.createAuthorityList(
				ROLE_A);
		List<GrantedAuthority> authorities2 = HierarchicalRolesTestHelper.createAuthorityList(
				ROLE_A, ROLE_B);

		RoleHierarchy roleHierarchy = RoleHierarchyBuilder
				.builder()
				.role(ROLE_A)
					.includes(ROLE_B)
					.build();

		assertThat(
				HierarchicalRolesTestHelper.containTheSameGrantedAuthoritiesCompareByAuthorityString(
						roleHierarchy.getReachableGrantedAuthorities(authorities0),
						authorities0)).isTrue();
		assertThat(
				HierarchicalRolesTestHelper.containTheSameGrantedAuthoritiesCompareByAuthorityString(
						roleHierarchy.getReachableGrantedAuthorities(authorities1),
						authorities2)).isTrue();
		assertThat(
				HierarchicalRolesTestHelper.containTheSameGrantedAuthoritiesCompareByAuthorityString(
						roleHierarchy.getReachableGrantedAuthorities(authorities2),
						authorities2)).isTrue();
	}
}
