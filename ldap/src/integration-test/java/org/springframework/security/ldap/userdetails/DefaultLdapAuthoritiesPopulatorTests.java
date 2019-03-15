/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
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

package org.springframework.security.ldap.userdetails;


import static org.junit.Assert.*;

import org.junit.*;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.ldap.AbstractLdapIntegrationTests;

import java.util.*;


/**
 *
 * @author Luke Taylor
 */
@SuppressWarnings({"deprecation"})
public class DefaultLdapAuthoritiesPopulatorTests extends AbstractLdapIntegrationTests {
    private DefaultLdapAuthoritiesPopulator populator;
    //~ Methods ========================================================================================================

    @Before
    public void setUp() throws Exception {
        populator = new DefaultLdapAuthoritiesPopulator(getContextSource(), "ou=groups");
        populator.setIgnorePartialResultException(false);
    }

    @Test
    public void defaultRoleIsAssignedWhenSet() {
        populator.setDefaultRole("ROLE_USER");
        assertSame(getContextSource(), populator.getContextSource());

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("cn=notfound"));

        Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(ctx, "notfound");
        assertEquals(1, authorities.size());
        assertTrue(AuthorityUtils.authorityListToSet(authorities).contains("ROLE_USER"));
    }

    @Test
    public void nullSearchBaseIsAccepted() throws Exception {
        populator = new DefaultLdapAuthoritiesPopulator(getContextSource(), null);
        populator.setDefaultRole("ROLE_USER");

        Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(
                new DirContextAdapter(new DistinguishedName("cn=notused")), "notused");
        assertEquals(1, authorities.size());
        assertTrue(AuthorityUtils.authorityListToSet(authorities).contains("ROLE_USER"));
    }

    @Test
    public void groupSearchReturnsExpectedRoles() {
        populator.setRolePrefix("ROLE_");
        populator.setGroupRoleAttribute("ou");
        populator.setSearchSubtree(true);
        populator.setSearchSubtree(false);
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(member={0})");

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

        Set<String> authorities = AuthorityUtils.authorityListToSet(populator.getGrantedAuthorities(ctx, "ben"));

        assertEquals("Should have 2 roles", 2, authorities.size());

        assertTrue(authorities.contains("ROLE_DEVELOPER"));
        assertTrue(authorities.contains("ROLE_MANAGER"));
    }

    @Test
    public void useOfUsernameParameterReturnsExpectedRoles() {
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(ou={1})");

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

        Set<String> authorities = AuthorityUtils.authorityListToSet(populator.getGrantedAuthorities(ctx, "manager"));

        assertEquals("Should have 1 role", 1, authorities.size());
        assertTrue(authorities.contains("ROLE_MANAGER"));
    }

    @Test
    public void subGroupRolesAreNotFoundByDefault() {
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

        Set<String> authorities = AuthorityUtils.authorityListToSet(populator.getGrantedAuthorities(ctx, "manager"));

        assertEquals("Should have 2 roles", 2, authorities.size());
        assertTrue(authorities.contains("ROLE_MANAGER"));
        assertTrue(authorities.contains("ROLE_DEVELOPER"));
    }

    @Test
    public void subGroupRolesAreFoundWhenSubtreeSearchIsEnabled() {
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);
        populator.setSearchSubtree(true);

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=ben,ou=people,dc=springframework,dc=org"));

        Set<String> authorities = AuthorityUtils.authorityListToSet(populator.getGrantedAuthorities(ctx, "manager"));

        assertEquals("Should have 3 roles", 3, authorities.size());
        assertTrue(authorities.contains("ROLE_MANAGER"));
        assertTrue(authorities.contains("ROLE_SUBMANAGER"));
        assertTrue(authorities.contains("ROLE_DEVELOPER"));
    }

    @Test
    public void extraRolesAreAdded() throws Exception {
        populator = new DefaultLdapAuthoritiesPopulator(getContextSource(), null) {
            @Override
            protected Set<GrantedAuthority> getAdditionalRoles(DirContextOperations user, String username) {
                return new HashSet<GrantedAuthority>(AuthorityUtils.createAuthorityList("ROLE_EXTRA"));
            }
        };

        Collection<GrantedAuthority> authorities = populator.getGrantedAuthorities(
                new DirContextAdapter(new DistinguishedName("cn=notused")), "notused");
        assertEquals(1, authorities.size());
        assertTrue(AuthorityUtils.authorityListToSet(authorities).contains("ROLE_EXTRA"));
    }

    @Test
    public void userDnWithEscapedCharacterParameterReturnsExpectedRoles() {
        populator.setGroupRoleAttribute("ou");
        populator.setConvertToUpperCase(true);
        populator.setGroupSearchFilter("(member={0})");

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("cn=mouse\\, jerry,ou=people,dc=springframework,dc=org"));

        Set<String> authorities = AuthorityUtils.authorityListToSet(populator.getGrantedAuthorities(ctx, "notused"));

        assertEquals("Should have 1 role", 1, authorities.size());
        assertTrue(authorities.contains("ROLE_MANAGER"));
    }
}
