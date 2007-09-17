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

package org.acegisecurity.userdetails.hierarchicalroles;

import junit.framework.TestCase;
import junit.textui.TestRunner;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

/**
 * Tests for {@link HierarchicalRolesTestHelper}.
 *
 * @author Michael Mayr
 */
public class TestHelperTests extends TestCase {

    public TestHelperTests() {
    }

    public TestHelperTests(String testCaseName) {
        super(testCaseName);
    }

    public void testContainTheSameGrantedAuthorities() {
        GrantedAuthority[] authorities1 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl("ROLE_B") };
        GrantedAuthority[] authorities2 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_B"), new GrantedAuthorityImpl("ROLE_A") };
        GrantedAuthority[] authorities3 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl("ROLE_C") };
        GrantedAuthority[] authorities4 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A") };
        GrantedAuthority[] authorities5 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl("ROLE_A") };

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
