/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.access.hierarchicalroles;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;

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

}
