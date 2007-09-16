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

import org.acegisecurity.ldap.AbstractLdapIntegrationTests;
import org.acegisecurity.ldap.InitialDirContextFactory;

import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;

import java.util.HashSet;
import java.util.Set;

import javax.naming.directory.BasicAttributes;


/**
 * DOCUMENT ME!
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultLdapAuthoritiesPopulatorTests extends AbstractLdapIntegrationTests {
    private DefaultLdapAuthoritiesPopulator populator;
    //~ Methods ========================================================================================================

    protected void onSetUp() throws Exception {
        super.onSetUp();

        populator = new DefaultLdapAuthoritiesPopulator((InitialDirContextFactory) getContextSource(), "ou=groups");

    }

    public void testDefaultRoleIsAssignedWhenSet() {

        populator.setDefaultRole("ROLE_USER");

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("cn=notfound"));

        GrantedAuthority[] authorities = populator.getGrantedAuthorities(ctx, "notfound");
        assertEquals(1, authorities.length);
        assertEquals("ROLE_USER", authorities[0].getAuthority());
    }

    public void testGroupSearchReturnsExpectedRoles() {
        populator.setRolePrefix("ROLE_");
        populator.setGroupRoleAttribute("ou");
        populator.setSearchSubtree(true);
        populator.setSearchSubtree(false);
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(member={0})");

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=acegisecurity,dc=org"));

        GrantedAuthority[] authorities = populator.getGrantedAuthorities(ctx, "ben");

        assertEquals("Should have 2 roles", 2, authorities.length);

        Set roles = new HashSet();
        roles.add(authorities[0].toString());
        roles.add(authorities[1].toString());
        assertTrue(roles.contains("ROLE_DEVELOPER"));
        assertTrue(roles.contains("ROLE_MANAGER"));
    }

    public void testUseOfUsernameParameterReturnsExpectedRoles() {
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(ou={1})");

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=acegisecurity,dc=org"));

        GrantedAuthority[] authorities = populator.getGrantedAuthorities(ctx, "manager");

        assertEquals("Should have 1 role", 1, authorities.length);
        assertEquals("ROLE_MANAGER", authorities[0].getAuthority());
    }

    public void testSubGroupRolesAreNotFoundByDefault() {
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=acegisecurity,dc=org"));

        GrantedAuthority[] authorities = populator.getGrantedAuthorities(ctx, "manager");

        assertEquals("Should have 2 roles", 2, authorities.length);
        Set roles = new HashSet(2);
        roles.add(authorities[0].getAuthority());
        roles.add(authorities[1].getAuthority());
        assertTrue(roles.contains("ROLE_MANAGER"));
        assertTrue(roles.contains("ROLE_DEVELOPER"));
    }

    public void testSubGroupRolesAreFoundWhenSubtreeSearchIsEnabled() {
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);
        populator.setSearchSubtree(true);

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=acegisecurity,dc=org"));

        GrantedAuthority[] authorities = populator.getGrantedAuthorities(ctx, "manager");

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
