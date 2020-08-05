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
package org.springframework.security.access.hierarchicalroles;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests for {@link RoleHierarchyImpl}.
 *
 * @author Michael Mayr
 */
public class RoleHierarchyImplTests {

	@Test
	public void testRoleHierarchyWithNullOrEmptyAuthorities() {
		List<GrantedAuthority> authorities0 = null;
		List<GrantedAuthority> authorities1 = new ArrayList<>();

		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B");

		assertThat(roleHierarchyImpl.getReachableGrantedAuthorities(authorities0)).isNotNull();
		assertThat(roleHierarchyImpl.getReachableGrantedAuthorities(authorities0)).isEmpty();

		assertThat(roleHierarchyImpl.getReachableGrantedAuthorities(authorities1)).isNotNull();
		assertThat(roleHierarchyImpl.getReachableGrantedAuthorities(authorities1)).isEmpty();
	}

	@Test
	public void testSimpleRoleHierarchy() {

		List<GrantedAuthority> authorities0 = AuthorityUtils.createAuthorityList("ROLE_0");
		List<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList("ROLE_A");
		List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B");

		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B");

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchyImpl.getReachableGrantedAuthorities(authorities0), authorities0)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchyImpl.getReachableGrantedAuthorities(authorities1), authorities2)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchyImpl.getReachableGrantedAuthorities(authorities2), authorities2)).isTrue();
	}

	@Test
	public void testTransitiveRoleHierarchies() {
		List<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList("ROLE_A");
		List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B", "ROLE_C");
		List<GrantedAuthority> authorities3 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B", "ROLE_C",
				"ROLE_D");

		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();

		roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_C");
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchyImpl.getReachableGrantedAuthorities(authorities1), authorities2)).isTrue();

		roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_C\nROLE_C > ROLE_D");
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchyImpl.getReachableGrantedAuthorities(authorities1), authorities3)).isTrue();
	}

	@Test
	public void testComplexRoleHierarchy() {
		List<GrantedAuthority> authoritiesInput1 = AuthorityUtils.createAuthorityList("ROLE_A");
		List<GrantedAuthority> authoritiesOutput1 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B", "ROLE_C",
				"ROLE_D");
		List<GrantedAuthority> authoritiesInput2 = AuthorityUtils.createAuthorityList("ROLE_B");
		List<GrantedAuthority> authoritiesOutput2 = AuthorityUtils.createAuthorityList("ROLE_B", "ROLE_D");
		List<GrantedAuthority> authoritiesInput3 = AuthorityUtils.createAuthorityList("ROLE_C");
		List<GrantedAuthority> authoritiesOutput3 = AuthorityUtils.createAuthorityList("ROLE_C", "ROLE_D");
		List<GrantedAuthority> authoritiesInput4 = AuthorityUtils.createAuthorityList("ROLE_D");
		List<GrantedAuthority> authoritiesOutput4 = AuthorityUtils.createAuthorityList("ROLE_D");

		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_A > ROLE_C\nROLE_C > ROLE_D\nROLE_B > ROLE_D");

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchyImpl.getReachableGrantedAuthorities(authoritiesInput1), authoritiesOutput1)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchyImpl.getReachableGrantedAuthorities(authoritiesInput2), authoritiesOutput2)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchyImpl.getReachableGrantedAuthorities(authoritiesInput3), authoritiesOutput3)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchyImpl.getReachableGrantedAuthorities(authoritiesInput4), authoritiesOutput4)).isTrue();
	}

	@Test
	public void testCyclesInRoleHierarchy() {
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();

		try {
			roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_A");
			fail("Cycle in role hierarchy was not detected!");
		}
		catch (CycleInRoleHierarchyException e) {
		}

		try {
			roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_A");
			fail("Cycle in role hierarchy was not detected!");
		}
		catch (CycleInRoleHierarchyException e) {
		}

		try {
			roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_C\nROLE_C > ROLE_A");
			fail("Cycle in role hierarchy was not detected!");
		}
		catch (CycleInRoleHierarchyException e) {
		}

		try {
			roleHierarchyImpl.setHierarchy(
					"ROLE_A > ROLE_B\nROLE_B > ROLE_C\nROLE_C > ROLE_E\nROLE_E > ROLE_D\nROLE_D > ROLE_B");
			fail("Cycle in role hierarchy was not detected!");
		}
		catch (CycleInRoleHierarchyException e) {
		}

		try {
			roleHierarchyImpl.setHierarchy("ROLE_C > ROLE_B\nROLE_B > ROLE_A\nROLE_A > ROLE_B");
			fail("Cycle in role hierarchy was not detected!");
		}
		catch (CycleInRoleHierarchyException e) {
		}
	}

	@Test
	public void testNoCyclesInRoleHierarchy() {
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();

		try {
			roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_A > ROLE_C\nROLE_C > ROLE_D\nROLE_B > ROLE_D");
		}
		catch (CycleInRoleHierarchyException e) {
			fail("A cycle in role hierarchy was incorrectly detected!");
		}
	}

	// SEC-863
	@Test
	public void testSimpleRoleHierarchyWithCustomGrantedAuthorityImplementation() {

		List<GrantedAuthority> authorities0 = HierarchicalRolesTestHelper.createAuthorityList("ROLE_0");
		List<GrantedAuthority> authorities1 = HierarchicalRolesTestHelper.createAuthorityList("ROLE_A");
		List<GrantedAuthority> authorities2 = HierarchicalRolesTestHelper.createAuthorityList("ROLE_A", "ROLE_B");

		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B");

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthoritiesCompareByAuthorityString(
				roleHierarchyImpl.getReachableGrantedAuthorities(authorities0), authorities0)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthoritiesCompareByAuthorityString(
				roleHierarchyImpl.getReachableGrantedAuthorities(authorities1), authorities2)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthoritiesCompareByAuthorityString(
				roleHierarchyImpl.getReachableGrantedAuthorities(authorities2), authorities2)).isTrue();
	}

	@Test
	public void testWhitespaceRoleHierarchies() {
		List<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList("ROLE A");
		List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE A", "ROLE B", "ROLE>C");
		List<GrantedAuthority> authorities3 = AuthorityUtils.createAuthorityList("ROLE A", "ROLE B", "ROLE>C",
				"ROLE D");

		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();

		roleHierarchyImpl.setHierarchy("ROLE A > ROLE B\nROLE B > ROLE>C");
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchyImpl.getReachableGrantedAuthorities(authorities1), authorities2)).isTrue();

		roleHierarchyImpl.setHierarchy("ROLE A > ROLE B\nROLE B > ROLE>C\nROLE>C > ROLE D");
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
				roleHierarchyImpl.getReachableGrantedAuthorities(authorities1), authorities3)).isTrue();
	}

	// gh-6954
	@Test
	public void testJavadoc() {
		List<GrantedAuthority> flatAuthorities = AuthorityUtils.createAuthorityList("ROLE_A");
		List<GrantedAuthority> allAuthorities = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B",
				"ROLE_AUTHENTICATED", "ROLE_UNAUTHENTICATED");
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy(
				"ROLE_A > ROLE_B\n" + "ROLE_B > ROLE_AUTHENTICATED\n" + "ROLE_AUTHENTICATED > ROLE_UNAUTHENTICATED");

		assertThat(roleHierarchyImpl.getReachableGrantedAuthorities(flatAuthorities))
				.containsExactlyInAnyOrderElementsOf(allAuthorities);
	}

	// gh-6954
	@Test
	public void testInterfaceJavadoc() {
		List<GrantedAuthority> flatAuthorities = AuthorityUtils.createAuthorityList("ROLE_HIGHEST");
		List<GrantedAuthority> allAuthorities = AuthorityUtils.createAuthorityList("ROLE_HIGHEST", "ROLE_HIGHER",
				"ROLE_LOW", "ROLE_LOWER");
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl
				.setHierarchy("ROLE_HIGHEST > ROLE_HIGHER\n" + "ROLE_HIGHER > ROLE_LOW\n" + "ROLE_LOW > ROLE_LOWER");

		assertThat(roleHierarchyImpl.getReachableGrantedAuthorities(flatAuthorities))
				.containsExactlyInAnyOrderElementsOf(allAuthorities);
	}

	// gh-6954
	@Test
	public void singleLineLargeHierarchy() {
		List<GrantedAuthority> flatAuthorities = AuthorityUtils.createAuthorityList("ROLE_HIGHEST");
		List<GrantedAuthority> allAuthorities = AuthorityUtils.createAuthorityList("ROLE_HIGHEST", "ROLE_HIGHER",
				"ROLE_LOW", "ROLE_LOWER");
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_HIGHEST > ROLE_HIGHER > ROLE_LOW > ROLE_LOWER");

		assertThat(roleHierarchyImpl.getReachableGrantedAuthorities(flatAuthorities))
				.containsExactlyInAnyOrderElementsOf(allAuthorities);
	}

}
