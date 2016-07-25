/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.springframework.security.access.hierarchicalroles.RoleHierarchyUtils.roleHierarchyFromMap;

/**
 * Tests for {@link RoleHierarchyUtils}.
 *
 * Copied from {@link RoleHierarchyImplTests} with adaptations for {@link RoleHierarchyUtils}.
 *
 * @author Thomas Darimont
 */
public class RoleHierarchyUtilsTests {

	@Test
	public void testRoleHierarchyWithNullOrEmptyAuthorities() {

		List<GrantedAuthority> authorities0 = null;
		List<GrantedAuthority> authorities1 = new ArrayList<GrantedAuthority>();

		RoleHierarchy roleHierarchy = roleHierarchyFromMap(singletonMap("ROLE_A", singletonList("ROLE_B")));

		assertThat(roleHierarchy.getReachableGrantedAuthorities(
				authorities0)).isNotNull();
		assertThat(
				roleHierarchy.getReachableGrantedAuthorities(authorities0)).isEmpty();
		;
		assertThat(roleHierarchy.getReachableGrantedAuthorities(
				authorities1)).isNotNull();
		assertThat(
				roleHierarchy.getReachableGrantedAuthorities(authorities1)).isEmpty();
		;
	}

	@Test
	public void testSimpleRoleHierarchy() {

		List<GrantedAuthority> authorities0 = AuthorityUtils.createAuthorityList(
				"ROLE_0");
		List<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList(
				"ROLE_A");
		List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_A",
				"ROLE_B");

		RoleHierarchy roleHierarchy = roleHierarchyFromMap(singletonMap("ROLE_A", singletonList("ROLE_B")));

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
				"ROLE_A");
		List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_A",
				"ROLE_B", "ROLE_C");
		List<GrantedAuthority> authorities3 = AuthorityUtils.createAuthorityList("ROLE_A",
				"ROLE_B", "ROLE_C", "ROLE_D");

		RoleHierarchy roleHierarchy2Levels = roleHierarchyFromMap(new HashMap<String, List<String>>(){
			{
				put("ROLE_A", asList("ROLE_B"));
				put("ROLE_B", asList("ROLE_C"));
			}
		});

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
			roleHierarchy2Levels.getReachableGrantedAuthorities(authorities1),
				authorities2)).isTrue();

		RoleHierarchy roleHierarchy3Levels = roleHierarchyFromMap(new HashMap<String, List<String>>(){
			{
				put("ROLE_A", asList("ROLE_B"));
				put("ROLE_B", asList("ROLE_C"));
				put("ROLE_C", asList("ROLE_D"));
			}
		});

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
			roleHierarchy3Levels.getReachableGrantedAuthorities(authorities1),
				authorities3)).isTrue();
	}

	@Test
	public void testComplexRoleHierarchy() {
		List<GrantedAuthority> authoritiesInput1 = AuthorityUtils.createAuthorityList(
				"ROLE_A");
		List<GrantedAuthority> authoritiesOutput1 = AuthorityUtils.createAuthorityList(
				"ROLE_A", "ROLE_B", "ROLE_C", "ROLE_D");
		List<GrantedAuthority> authoritiesInput2 = AuthorityUtils.createAuthorityList(
				"ROLE_B");
		List<GrantedAuthority> authoritiesOutput2 = AuthorityUtils.createAuthorityList(
				"ROLE_B", "ROLE_D");
		List<GrantedAuthority> authoritiesInput3 = AuthorityUtils.createAuthorityList(
				"ROLE_C");
		List<GrantedAuthority> authoritiesOutput3 = AuthorityUtils.createAuthorityList(
				"ROLE_C", "ROLE_D");
		List<GrantedAuthority> authoritiesInput4 = AuthorityUtils.createAuthorityList(
				"ROLE_D");
		List<GrantedAuthority> authoritiesOutput4 = AuthorityUtils.createAuthorityList(
				"ROLE_D");


		RoleHierarchy roleHierarchy3LevelsMultipleRoles = roleHierarchyFromMap(new HashMap<String, List<String>>(){
			{
				put("ROLE_A", asList("ROLE_B","ROLE_C"));
				put("ROLE_B", asList("ROLE_D"));
				put("ROLE_C", asList("ROLE_D"));
			}
		});

		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
			roleHierarchy3LevelsMultipleRoles.getReachableGrantedAuthorities(authoritiesInput1),
				authoritiesOutput1)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
			roleHierarchy3LevelsMultipleRoles.getReachableGrantedAuthorities(authoritiesInput2),
				authoritiesOutput2)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
			roleHierarchy3LevelsMultipleRoles.getReachableGrantedAuthorities(authoritiesInput3),
				authoritiesOutput3)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(
			roleHierarchy3LevelsMultipleRoles.getReachableGrantedAuthorities(authoritiesInput4),
				authoritiesOutput4)).isTrue();
	}

	@Test
	public void testCyclesInRoleHierarchy() {

		try {
			roleHierarchyFromMap(singletonMap("ROLE_A", singletonList("ROLE_A")));
			fail("Cycle in role hierarchy was not detected!");
		}
		catch (CycleInRoleHierarchyException e) {
		}

		try {

			roleHierarchyFromMap(new HashMap<String, List<String>>(){
				{
					put("ROLE_A", asList("ROLE_B"));
					put("ROLE_B", asList("ROLE_A"));
				}
			});

			fail("Cycle in role hierarchy was not detected!");
		}
		catch (CycleInRoleHierarchyException e) {
		}

		try {

			roleHierarchyFromMap(new HashMap<String, List<String>>(){
				{
					put("ROLE_A", asList("ROLE_B"));
					put("ROLE_B", asList("ROLE_C"));
					put("ROLE_C", asList("ROLE_A"));
				}
			});

			fail("Cycle in role hierarchy was not detected!");
		}
		catch (CycleInRoleHierarchyException e) {
		}

		try {

			roleHierarchyFromMap(new HashMap<String, List<String>>(){
				{
					put("ROLE_A", asList("ROLE_B"));
					put("ROLE_B", asList("ROLE_C"));
					put("ROLE_C", asList("ROLE_E"));
					put("ROLE_E", asList("ROLE_D"));
					put("ROLE_D", asList("ROLE_B"));
				}
			});


			fail("Cycle in role hierarchy was not detected!");
		}
		catch (CycleInRoleHierarchyException e) {
		}
	}

	@Test
	public void testNoCyclesInRoleHierarchy() {
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();

		try {
			roleHierarchyImpl.setHierarchy(
					"ROLE_A > ROLE_B\nROLE_A > ROLE_C\nROLE_C > ROLE_D\nROLE_B > ROLE_D");

			roleHierarchyFromMap(new HashMap<String, List<String>>(){
				{
					put("ROLE_A", asList("ROLE_B"));
					put("ROLE_A", asList("ROLE_C"));
					put("ROLE_C", asList("ROLE_D"));
					put("ROLE_B", asList("ROLE_D"));
				}
			});

		}
		catch (CycleInRoleHierarchyException e) {
			fail("A cycle in role hierarchy was incorrectly detected!");
		}
	}

	@Test
	public void testSimpleRoleHierarchyWithCustomGrantedAuthorityImplementation() {

		List<GrantedAuthority> authorities0 = HierarchicalRolesTestHelper.createAuthorityList(
				"ROLE_0");
		List<GrantedAuthority> authorities1 = HierarchicalRolesTestHelper.createAuthorityList(
				"ROLE_A");
		List<GrantedAuthority> authorities2 = HierarchicalRolesTestHelper.createAuthorityList(
				"ROLE_A", "ROLE_B");

		RoleHierarchy roleHierarchy = roleHierarchyFromMap(singletonMap("ROLE_A", singletonList("ROLE_B")));

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
