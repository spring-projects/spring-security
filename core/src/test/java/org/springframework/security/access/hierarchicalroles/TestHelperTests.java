/*
 * Copyright 2002-2017 the original author or authors.
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
import java.util.Collection;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.junit.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link HierarchicalRolesTestHelper}.
 *
 * @author Michael Mayr
 */
public class TestHelperTests {

	@Test
	public void testContainTheSameGrantedAuthorities() {
		List<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B");
		List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_B", "ROLE_A");
		List<GrantedAuthority> authorities3 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_C");
		List<GrantedAuthority> authorities4 = AuthorityUtils.createAuthorityList("ROLE_A");
		List<GrantedAuthority> authorities5 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_A");
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(null, null)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities1)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities2)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities2, authorities1)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(null, authorities1)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, null)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities3)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities3, authorities1)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities4)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities4, authorities1)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities4, authorities5)).isFalse();
	}

	// SEC-863
	@Test
	public void testToListOfAuthorityStrings() {
		Collection<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B");
		Collection<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_B", "ROLE_A");
		Collection<GrantedAuthority> authorities3 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_C");
		Collection<GrantedAuthority> authorities4 = AuthorityUtils.createAuthorityList("ROLE_A");
		Collection<GrantedAuthority> authorities5 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_A");
		List<String> authoritiesStrings1 = new ArrayList<>();
		authoritiesStrings1.add("ROLE_A");
		authoritiesStrings1.add("ROLE_B");
		List<String> authoritiesStrings2 = new ArrayList<>();
		authoritiesStrings2.add("ROLE_B");
		authoritiesStrings2.add("ROLE_A");
		List<String> authoritiesStrings3 = new ArrayList<>();
		authoritiesStrings3.add("ROLE_A");
		authoritiesStrings3.add("ROLE_C");
		List<String> authoritiesStrings4 = new ArrayList<>();
		authoritiesStrings4.add("ROLE_A");
		List<String> authoritiesStrings5 = new ArrayList<>();
		authoritiesStrings5.add("ROLE_A");
		authoritiesStrings5.add("ROLE_A");
		assertThat(CollectionUtils.isEqualCollection(
				HierarchicalRolesTestHelper.toCollectionOfAuthorityStrings(authorities1), authoritiesStrings1))
						.isTrue();
		assertThat(CollectionUtils.isEqualCollection(
				HierarchicalRolesTestHelper.toCollectionOfAuthorityStrings(authorities2), authoritiesStrings2))
						.isTrue();
		assertThat(CollectionUtils.isEqualCollection(
				HierarchicalRolesTestHelper.toCollectionOfAuthorityStrings(authorities3), authoritiesStrings3))
						.isTrue();
		assertThat(CollectionUtils.isEqualCollection(
				HierarchicalRolesTestHelper.toCollectionOfAuthorityStrings(authorities4), authoritiesStrings4))
						.isTrue();
		assertThat(CollectionUtils.isEqualCollection(
				HierarchicalRolesTestHelper.toCollectionOfAuthorityStrings(authorities5), authoritiesStrings5))
						.isTrue();
	}

	// SEC-863
	@Test
	public void testContainTheSameGrantedAuthoritiesCompareByAuthorityString() {
		List<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B");
		List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_B", "ROLE_A");
		List<GrantedAuthority> authorities3 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_C");
		List<GrantedAuthority> authorities4 = AuthorityUtils.createAuthorityList("ROLE_A");
		List<GrantedAuthority> authorities5 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_A");
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(null, null)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities1)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities2)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities2, authorities1)).isTrue();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(null, authorities1)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, null)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities3)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities3, authorities1)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities4)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities4, authorities1)).isFalse();
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities4, authorities5)).isFalse();
	}

	// SEC-863
	@Test
	public void testContainTheSameGrantedAuthoritiesCompareByAuthorityStringWithAuthorityLists() {
		List<GrantedAuthority> authorities1 = HierarchicalRolesTestHelper.createAuthorityList("ROLE_A", "ROLE_B");
		List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B");
		assertThat(HierarchicalRolesTestHelper.containTheSameGrantedAuthoritiesCompareByAuthorityString(authorities1,
				authorities2)).isTrue();
	}

	// SEC-863
	@Test
	public void testCreateAuthorityList() {
		List<GrantedAuthority> authorities1 = HierarchicalRolesTestHelper.createAuthorityList("ROLE_A");
		assertThat(authorities1).hasSize(1);
		assertThat(authorities1.get(0).getAuthority()).isEqualTo("ROLE_A");
		List<GrantedAuthority> authorities2 = HierarchicalRolesTestHelper.createAuthorityList("ROLE_A", "ROLE_C");
		assertThat(authorities2).hasSize(2);
		assertThat(authorities2.get(0).getAuthority()).isEqualTo("ROLE_A");
		assertThat(authorities2.get(1).getAuthority()).isEqualTo("ROLE_C");
	}

}
