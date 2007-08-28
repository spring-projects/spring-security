/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
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

package org.acegisecurity.providers.ldap.populator;

import org.acegisecurity.GrantedAuthority;

import org.acegisecurity.ldap.AbstractLdapServerTestCase;

import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;

import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;

import javax.naming.directory.BasicAttributes;


/**
 * DOCUMENT ME!
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultLdapAuthoritiesPopulatorTests extends AbstractLdapServerTestCase {
    //~ Methods ========================================================================================================

    public void onSetUp() {
        getInitialCtxFactory().setManagerDn(MANAGER_USER);
        getInitialCtxFactory().setManagerPassword(MANAGER_PASSWORD);
    }

//    public void testUserAttributeMappingToRoles() {
//        DefaultLdapAuthoritiesPopulator populator = new DefaultLdapAuthoritiesPopulator();
//        populator.setUserRoleAttributes(new String[] {"userRole", "otherUserRole"});
//        populator.getUserRoleAttributes();
//
//        Attributes userAttrs = new BasicAttributes();
//        BasicAttribute attr = new BasicAttribute("userRole", "role1");
//        attr.add("role2");
//        userAttrs.put(attr);
//        attr = new BasicAttribute("otherUserRole", "role3");
//        attr.add("role2"); // duplicate
//        userAttrs.put(attr);
//
//        LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
//        user.setDn("Ignored");
//        user.setUsername("Ignored");
//        user.setAttributes(userAttrs);
//
//        GrantedAuthority[] authorities =
//                populator.getGrantedAuthorities(user.createUserDetails());
//        assertEquals("User should have three roles", 3, authorities.length);

    //    }
    public void testDefaultRoleIsAssignedWhenSet() {
        DefaultLdapAuthoritiesPopulator populator = new DefaultLdapAuthoritiesPopulator(getInitialCtxFactory(),
                "ou=groups");
        populator.setDefaultRole("ROLE_USER");

        LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
        user.setDn("cn=notfound");
        user.setUsername("notfound");
        user.setAttributes(new BasicAttributes());

        GrantedAuthority[] authorities = populator.getGrantedAuthorities(user.createUserDetails());
        assertEquals(1, authorities.length);
        assertEquals("ROLE_USER", authorities[0].getAuthority());
    }

    public void testGroupSearchReturnsExpectedRoles() {
        DefaultLdapAuthoritiesPopulator populator = new DefaultLdapAuthoritiesPopulator(getInitialCtxFactory(),
                "ou=groups");
        populator.setRolePrefix("ROLE_");
        populator.setGroupRoleAttribute("ou");
        populator.setSearchSubtree(true);
        populator.setSearchSubtree(false);
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(member={0})");

        LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
        user.setUsername("ben");
        user.setDn("uid=ben,ou=people,dc=acegisecurity,dc=org");
        user.setAttributes(new BasicAttributes());

        GrantedAuthority[] authorities = populator.getGrantedAuthorities(user.createUserDetails());

        assertEquals("Should have 2 roles", 2, authorities.length);

        Set roles = new HashSet();
        roles.add(authorities[0].toString());
        roles.add(authorities[1].toString());
        assertTrue(roles.contains("ROLE_DEVELOPER"));
        assertTrue(roles.contains("ROLE_MANAGER"));
    }

    public void testUseOfUsernameParameterReturnsExpectedRoles() {
        DefaultLdapAuthoritiesPopulator populator = new DefaultLdapAuthoritiesPopulator(getInitialCtxFactory(),
                "ou=groups");
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(ou={1})");

        LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
        user.setUsername("manager");
        user.setDn("uid=ben,ou=people,dc=acegisecurity,dc=org");

        GrantedAuthority[] authorities = populator.getGrantedAuthorities(user.createUserDetails());
        assertEquals("Should have 1 role", 1, authorities.length);
        assertEquals("ROLE_MANAGER", authorities[0].getAuthority());
    }

    public void testSubGroupRolesAreNotFoundByDefault() {
        DefaultLdapAuthoritiesPopulator populator = new DefaultLdapAuthoritiesPopulator(getInitialCtxFactory(),
                "ou=groups");
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);

        LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
        user.setUsername("manager");
        user.setDn("uid=ben,ou=people,dc=acegisecurity,dc=org");

        GrantedAuthority[] authorities = populator.getGrantedAuthorities(user.createUserDetails());
        assertEquals("Should have 2 roles", 2, authorities.length);
        Set roles = new HashSet(2);
        roles.add(authorities[0].getAuthority());
        roles.add(authorities[1].getAuthority());
        assertTrue(roles.contains("ROLE_MANAGER"));
        assertTrue(roles.contains("ROLE_DEVELOPER"));
    }

    public void testSubGroupRolesAreFoundWhenSubtreeSearchIsEnabled() {
        DefaultLdapAuthoritiesPopulator populator = new DefaultLdapAuthoritiesPopulator(getInitialCtxFactory(),
                "ou=groups");
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);
        populator.setSearchSubtree(true);

        LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
        user.setUsername("manager");
        user.setDn("uid=ben,ou=people,dc=acegisecurity,dc=org");

        GrantedAuthority[] authorities = populator.getGrantedAuthorities(user.createUserDetails());
        assertEquals("Should have 3 roles", 3, authorities.length);
        Set roles = new HashSet(3);
        roles.add(authorities[0].getAuthority());
        roles.add(authorities[1].getAuthority());
        roles.add(authorities[2].getAuthority());
        assertTrue(roles.contains("ROLE_MANAGER"));
        assertTrue(roles.contains("ROLE_DEVELOPER"));
        assertTrue(roles.contains("ROLE_SUBMANAGER"));
    }

}
