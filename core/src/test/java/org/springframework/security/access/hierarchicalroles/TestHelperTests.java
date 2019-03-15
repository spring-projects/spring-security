/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.access.hierarchicalroles;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * Tests for {@link HierarchicalRolesTestHelper}.
 *
 * @author Michael Mayr
 */
public class TestHelperTests {

    @Test
    public void testContainTheSameGrantedAuthorities() {
        List<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList("ROLE_A","ROLE_B");
        List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_B","ROLE_A");
        List<GrantedAuthority> authorities3 = AuthorityUtils.createAuthorityList("ROLE_A","ROLE_C");
        List<GrantedAuthority> authorities4 = AuthorityUtils.createAuthorityList("ROLE_A");
        List<GrantedAuthority> authorities5 = AuthorityUtils.createAuthorityList("ROLE_A","ROLE_A");

        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(null, null));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities1));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities2));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities2, authorities1));

        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(null, authorities1));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, null));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities3));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities3, authorities1));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities4));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities4, authorities1));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities4, authorities5));
    }

    // SEC-863
    @Test
    public void testToListOfAuthorityStrings() {
        Collection<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B");
        Collection<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_B", "ROLE_A");
        Collection<GrantedAuthority> authorities3 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_C");
        Collection<GrantedAuthority> authorities4 = AuthorityUtils.createAuthorityList("ROLE_A");
        Collection<GrantedAuthority> authorities5 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_A");

        List<String> authoritiesStrings1 = new ArrayList<String>();
        authoritiesStrings1.add("ROLE_A");
        authoritiesStrings1.add("ROLE_B");

        List<String> authoritiesStrings2 = new ArrayList<String>();
        authoritiesStrings2.add("ROLE_B");
        authoritiesStrings2.add("ROLE_A");

        List<String> authoritiesStrings3 = new ArrayList<String>();
        authoritiesStrings3.add("ROLE_A");
        authoritiesStrings3.add("ROLE_C");

        List<String> authoritiesStrings4 = new ArrayList<String>();
        authoritiesStrings4.add("ROLE_A");

        List<String> authoritiesStrings5 = new ArrayList<String>();
        authoritiesStrings5.add("ROLE_A");
        authoritiesStrings5.add("ROLE_A");

        assertTrue(CollectionUtils.isEqualCollection(
                HierarchicalRolesTestHelper.toCollectionOfAuthorityStrings(authorities1), authoritiesStrings1));

        assertTrue(CollectionUtils.isEqualCollection(
                HierarchicalRolesTestHelper.toCollectionOfAuthorityStrings(authorities2), authoritiesStrings2));

        assertTrue(CollectionUtils.isEqualCollection(
                HierarchicalRolesTestHelper.toCollectionOfAuthorityStrings(authorities3), authoritiesStrings3));

        assertTrue(CollectionUtils.isEqualCollection(
                HierarchicalRolesTestHelper.toCollectionOfAuthorityStrings(authorities4), authoritiesStrings4));

        assertTrue(CollectionUtils.isEqualCollection(
                HierarchicalRolesTestHelper.toCollectionOfAuthorityStrings(authorities5), authoritiesStrings5));
    }

    // SEC-863
    @Test
    public void testContainTheSameGrantedAuthoritiesCompareByAuthorityString() {
        List<GrantedAuthority> authorities1 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B");
        List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_B", "ROLE_A");
        List<GrantedAuthority> authorities3 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_C");
        List<GrantedAuthority> authorities4 = AuthorityUtils.createAuthorityList("ROLE_A");
        List<GrantedAuthority> authorities5 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_A");

        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(null, null));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities1));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities2));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities2, authorities1));

        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(null, authorities1));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, null));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities3));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities3, authorities1));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities1, authorities4));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities4, authorities1));
        assertFalse(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(authorities4, authorities5));
    }

    // SEC-863
    @Test
    public void testContainTheSameGrantedAuthoritiesCompareByAuthorityStringWithAuthorityLists() {
        List<GrantedAuthority> authorities1 = HierarchicalRolesTestHelper.createAuthorityList("ROLE_A", "ROLE_B");
        List<GrantedAuthority> authorities2 = AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B");
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthoritiesCompareByAuthorityString(authorities1, authorities2));
    }

    // SEC-863
    @Test
    public void testCreateAuthorityList() {
        List<GrantedAuthority> authorities1 = HierarchicalRolesTestHelper.createAuthorityList("ROLE_A");
        assertEquals(authorities1.size(), 1);
        assertEquals("ROLE_A", authorities1.get(0).getAuthority());

        List<GrantedAuthority> authorities2 = HierarchicalRolesTestHelper.createAuthorityList("ROLE_A", "ROLE_C");
        assertEquals(authorities2.size(), 2);
        assertEquals("ROLE_A", authorities2.get(0).getAuthority());
        assertEquals("ROLE_C", authorities2.get(1).getAuthority());
    }
}
