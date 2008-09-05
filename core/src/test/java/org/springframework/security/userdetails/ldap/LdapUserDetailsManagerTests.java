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
package org.springframework.security.userdetails.ldap;

import org.springframework.security.BadCredentialsException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.ldap.AbstractLdapIntegrationTests;
import org.springframework.security.ldap.DefaultLdapUsernameToDnMapper;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.ldap.core.DirContextAdapter;

import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Test;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetailsManagerTests extends AbstractLdapIntegrationTests {
    private static final GrantedAuthority[] TEST_AUTHORITIES = new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_CLOWNS"),
                new GrantedAuthorityImpl("ROLE_ACROBATS")};
    private LdapUserDetailsManager mgr;
    private SpringSecurityLdapTemplate template;

    public void onSetUp() throws Exception {
        super.onSetUp();
        mgr = new LdapUserDetailsManager(getContextSource());
        template = new SpringSecurityLdapTemplate(getContextSource());
        DirContextAdapter ctx = new DirContextAdapter();

        ctx.setAttributeValue("objectclass", "organizationalUnit");
        ctx.setAttributeValue("ou", "test people");
        template.bind("ou=test people", ctx, null);

        ctx.setAttributeValue("ou", "testgroups");
        template.bind("ou=testgroups", ctx, null);

        DirContextAdapter group = new DirContextAdapter();

        group.setAttributeValue("objectclass", "groupOfNames");
        group.setAttributeValue("cn", "clowns");
        group.setAttributeValue("member", "cn=nobody,ou=test people,dc=springframework,dc=org");
        template.bind("cn=clowns,ou=testgroups", group, null);

        group.setAttributeValue("cn", "acrobats");
        template.bind("cn=acrobats,ou=testgroups", group, null);

        mgr.setUsernameMapper(new DefaultLdapUsernameToDnMapper("ou=test people","uid"));
        mgr.setGroupSearchBase("ou=testgroups");
        mgr.setGroupRoleAttributeName("cn");
        mgr.setGroupMemberAttributeName("member");
        mgr.setUserDetailsMapper(new PersonContextMapper());
    }

    @After
    public void onTearDown() throws Exception {
//        Iterator people = template.list("ou=testpeople").iterator();

//        DirContext rootCtx = new DirContextAdapter(new DistinguishedName(getInitialCtxFactory().getRootDn()));
//
//        while(people.hasNext()) {
//            template.unbind((String) people.next() + ",ou=testpeople");
//        }

        template.unbind("ou=test people",true);
        template.unbind("ou=testgroups",true);

        SecurityContextHolder.clearContext();
    }

    @Test
    public void testLoadUserByUsernameReturnsCorrectData() {
        mgr.setUsernameMapper(new DefaultLdapUsernameToDnMapper("ou=people","uid"));
        mgr.setGroupSearchBase("ou=groups");
        LdapUserDetails bob = (LdapUserDetails) mgr.loadUserByUsername("bob");
        assertEquals("bob", bob.getUsername());
        assertEquals("uid=bob, ou=people, dc=springframework, dc=org", bob.getDn());
        assertEquals("bobspassword", bob.getPassword());

        assertEquals(1, bob.getAuthorities().length);
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testLoadingInvalidUsernameThrowsUsernameNotFoundException() {
        mgr.loadUserByUsername("jim");
    }

    @Test
    public void testUserExistsReturnsTrueForValidUser() {
        mgr.setUsernameMapper(new DefaultLdapUsernameToDnMapper("ou=people","uid"));
        assertTrue(mgr.userExists("bob"));
    }

    @Test
    public void testUserExistsReturnsFalseForInValidUser() {
        assertFalse(mgr.userExists("jim"));
    }

    @Test
    public void testCreateNewUserSucceeds() {
        InetOrgPerson.Essence p = new InetOrgPerson.Essence();
        p.setCarLicense("XXX");
        p.setCn(new String[] {"Joe Smeth"});
        p.setDepartmentNumber("5679");
        p.setDescription("Some description");
        p.setDn("whocares");
        p.setEmployeeNumber("E781");
        p.setInitials("J");
        p.setMail("joe@smeth.com");
        p.setMobile("+44776542911");
        p.setOu("Joes Unit");
        p.setO("Organization");
        p.setRoomNumber("500X");
        p.setSn("Smeth");
        p.setUid("joe");

        p.setAuthorities(TEST_AUTHORITIES);

        mgr.createUser(p.createUserDetails());
    }

    @Test
    public void testDeleteUserSucceeds() {
        InetOrgPerson.Essence p = new InetOrgPerson.Essence();
        p.setDn("whocares");
        p.setCn(new String[] {"Don Smeth"});
        p.setSn("Smeth");
        p.setUid("don");
        p.setAuthorities(TEST_AUTHORITIES);

        mgr.createUser(p.createUserDetails());
        mgr.setUserDetailsMapper(new InetOrgPersonContextMapper());

        InetOrgPerson don = (InetOrgPerson) mgr.loadUserByUsername("don");

        assertEquals(2, don.getAuthorities().length);

        mgr.deleteUser("don");

        try {
            mgr.loadUserByUsername("don");
            fail("Expected UsernameNotFoundException after deleting user");
        } catch(UsernameNotFoundException expected) {
            // expected
        }

        // Check that no authorities are left
        assertEquals(0, mgr.getUserAuthorities(mgr.usernameMapper.buildDn("don"), "don").length);
    }

    @Test
    public void testPasswordChangeWithCorrectOldPasswordSucceeds() {
        InetOrgPerson.Essence p = new InetOrgPerson.Essence();
        p.setDn("whocares");
        p.setCn(new String[] {"John Yossarian"});
        p.setSn("Yossarian");
        p.setUid("johnyossarian");
        p.setPassword("yossarianspassword");
        p.setAuthorities(TEST_AUTHORITIES);

        mgr.createUser(p.createUserDetails());

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("johnyossarian", "yossarianspassword", TEST_AUTHORITIES));

        mgr.changePassword("yossarianspassword", "yossariansnewpassword");

        assertTrue(template.compare("uid=johnyossarian,ou=test people",
                "userPassword", "yossariansnewpassword"));
    }

    @Test(expected = BadCredentialsException.class)
    public void testPasswordChangeWithWrongOldPasswordFails() {
        InetOrgPerson.Essence p = new InetOrgPerson.Essence();
        p.setDn("whocares");
        p.setCn(new String[] {"John Yossarian"});
        p.setSn("Yossarian");
        p.setUid("johnyossarian");
        p.setPassword("yossarianspassword");
        p.setAuthorities(TEST_AUTHORITIES);

        mgr.createUser(p.createUserDetails());

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("johnyossarian", "yossarianspassword", TEST_AUTHORITIES));

        mgr.changePassword("wrongpassword", "yossariansnewpassword");
    }
}
