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

package org.springframework.security.ldap.populator;

import org.springframework.security.GrantedAuthority;

import org.springframework.security.ldap.AbstractLdapIntegrationTests;
import org.springframework.security.ldap.populator.DefaultLdapAuthoritiesPopulator;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;
import org.junit.Test;


/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultLdapAuthoritiesPopulatorTests extends AbstractLdapIntegrationTests {
    private DefaultLdapAuthoritiesPopulator populator;
    //~ Methods ========================================================================================================

    public void onSetUp() throws Exception {
        super.onSetUp();

        populator = new DefaultLdapAuthoritiesPopulator(getContextSource(), "ou=groups");
    }

    @Test
    public void testDefaultRoleIsAssignedWhenSet() {

        populator.setDefaultRole("ROLE_USER");

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("cn=notfound"));

        List<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "notfound");
        assertEquals(1, authorities.size());
        assertEquals("ROLE_USER", authorities.get(0).getAuthority());
    }

    @Test
    public void testGroupSearchReturnsExpectedRoles() {
        populator.setRolePrefix("ROLE_");
        populator.setGroupRoleAttribute("ou");
        populator.setSearchSubtree(true);
        populator.setSearchSubtree(false);
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(member={0})");

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

        List<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "ben");

        assertEquals("Should have 2 roles", 2, authorities.size());

        Set<String> roles = new HashSet<String>();
        roles.add(authorities.get(0).toString());
        roles.add(authorities.get(1).toString());
        assertTrue(roles.contains("ROLE_DEVELOPER"));
        assertTrue(roles.contains("ROLE_MANAGER"));
    }

    @Test
    public void testUseOfUsernameParameterReturnsExpectedRoles() {
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(ou={1})");

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

        List<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "manager");

        assertEquals("Should have 1 role", 1, authorities.size());
        assertEquals("ROLE_MANAGER", authorities.get(0).getAuthority());
    }

    @Test
    public void testSubGroupRolesAreNotFoundByDefault() {
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

        List<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "manager");

        assertEquals("Should have 2 roles", 2, authorities.size());
        Set<String> roles = new HashSet<String>(2);
        roles.add(authorities.get(0).getAuthority());
        roles.add(authorities.get(1).getAuthority());
        assertTrue(roles.contains("ROLE_MANAGER"));
        assertTrue(roles.contains("ROLE_DEVELOPER"));
    }

    @Test
    public void testSubGroupRolesAreFoundWhenSubtreeSearchIsEnabled() {
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);
        populator.setSearchSubtree(true);

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

        List<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "manager");

        assertEquals("Should have 3 roles", 3, authorities.size());
        Set<String> roles = new HashSet<String>(3);
        roles.add(authorities.get(0).getAuthority());
        roles.add(authorities.get(1).getAuthority());
        roles.add(authorities.get(2).getAuthority());
        assertTrue(roles.contains("ROLE_MANAGER"));
        assertTrue(roles.contains("ROLE_DEVELOPER"));
        assertTrue(roles.contains("ROLE_SUBMANAGER"));
    }

    @Test
    public void testUserDnWithEscapedCharacterParameterReturnsExpectedRoles() {
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(member={0})");

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("cn=mouse\\, jerry,ou=people,dc=springframework,dc=org"));

        List<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "notused");

        assertEquals("Should have 1 role", 1, authorities.size());
        assertEquals("ROLE_MANAGER", authorities.get(0).getAuthority());
    }

}
