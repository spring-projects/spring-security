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
 * Tests for {@link RoleHierarchyImpl}.
 *
 * @author Michael Mayr
 */
public class RoleHierarchyImplTests extends TestCase {

    public RoleHierarchyImplTests() {
    }

    public RoleHierarchyImplTests(String testCaseName) {
        super(testCaseName);
    }

    public void testSimpleRoleHierarchy() {
        GrantedAuthority[] authorities0 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_0") };
        GrantedAuthority[] authorities1 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A") };
        GrantedAuthority[] authorities2 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl("ROLE_B") };

        RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
        roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B");

        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(roleHierarchyImpl.getReachableGrantedAuthorities(authorities0), authorities0));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(roleHierarchyImpl.getReachableGrantedAuthorities(authorities1), authorities2));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(roleHierarchyImpl.getReachableGrantedAuthorities(authorities2), authorities2));
    }

    public void testTransitiveRoleHierarchies() {
        GrantedAuthority[] authorities1 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A") };
        GrantedAuthority[] authorities2 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl("ROLE_B"), new GrantedAuthorityImpl("ROLE_C") };
        GrantedAuthority[] authorities3 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl("ROLE_B"), new GrantedAuthorityImpl("ROLE_C"),
                                                                   new GrantedAuthorityImpl("ROLE_D") };

        RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();

        roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_C");
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(roleHierarchyImpl.getReachableGrantedAuthorities(authorities1), authorities2));

        roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_C\nROLE_C > ROLE_D");
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(roleHierarchyImpl.getReachableGrantedAuthorities(authorities1), authorities3));
    }

    public void testComplexRoleHierarchy() {
        GrantedAuthority[] authoritiesInput1 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A") };
        GrantedAuthority[] authoritiesOutput1 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl("ROLE_B"), new GrantedAuthorityImpl("ROLE_C"),
                                                                         new GrantedAuthorityImpl("ROLE_D") };
        GrantedAuthority[] authoritiesInput2 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_B") };
        GrantedAuthority[] authoritiesOutput2 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_B"), new GrantedAuthorityImpl("ROLE_D") };
        GrantedAuthority[] authoritiesInput3 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_C") };
        GrantedAuthority[] authoritiesOutput3 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_C"), new GrantedAuthorityImpl("ROLE_D") };
        GrantedAuthority[] authoritiesInput4 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_D") };
        GrantedAuthority[] authoritiesOutput4 = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_D") };

        RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
        roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_A > ROLE_C\nROLE_C > ROLE_D\nROLE_B > ROLE_D");

        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(roleHierarchyImpl.getReachableGrantedAuthorities(authoritiesInput1), authoritiesOutput1));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(roleHierarchyImpl.getReachableGrantedAuthorities(authoritiesInput2), authoritiesOutput2));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(roleHierarchyImpl.getReachableGrantedAuthorities(authoritiesInput3), authoritiesOutput3));
        assertTrue(HierarchicalRolesTestHelper.containTheSameGrantedAuthorities(roleHierarchyImpl.getReachableGrantedAuthorities(authoritiesInput4), authoritiesOutput4));
    }

    public void testCyclesInRoleHierarchy() {
        RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();

        try {
            roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_A");
            fail("Cycle in role hierarchy was not detected!");
        } catch (CycleInRoleHierarchyException e) {}

        try {
            roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_A");
            fail("Cycle in role hierarchy was not detected!");
        } catch (CycleInRoleHierarchyException e) {}

        try {
            roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_C\nROLE_C > ROLE_A");
            fail("Cycle in role hierarchy was not detected!");
        } catch (CycleInRoleHierarchyException e) {}

        try {
            roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_B > ROLE_C\nROLE_C > ROLE_E\nROLE_E > ROLE_D\nROLE_D > ROLE_B");
            fail("Cycle in role hierarchy was not detected!");
        } catch (CycleInRoleHierarchyException e) {}
    }

    public void testNoCyclesInRoleHierarchy() {
        RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();

        try {
            roleHierarchyImpl.setHierarchy("ROLE_A > ROLE_B\nROLE_A > ROLE_C\nROLE_C > ROLE_D\nROLE_B > ROLE_D");
        } catch (CycleInRoleHierarchyException e) {
            fail("A cycle in role hierarchy was incorrectly detected!");
        }
    }

}