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

import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.AbstractLdapIntegrationTests;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.context.SecurityContextHolder;

import org.springframework.ldap.core.DirContextAdapter;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetailsManagerTests extends AbstractLdapIntegrationTests {
    private static final GrantedAuthority[] TEST_AUTHORITIES = new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_CLOWNS"),
                new GrantedAuthorityImpl("ROLE_ACROBATS")};
    private LdapUserDetailsManager mgr;
    private SpringSecurityLdapTemplate template;

    protected void onSetUp() throws Exception {
        super.onSetUp();
        mgr = new LdapUserDetailsManager(getContextSource());
        template = new SpringSecurityLdapTemplate(getContextSource());
        DirContextAdapter ctx = new DirContextAdapter();

        ctx.setAttributeValue("objectclass", "organizationalUnit");
        ctx.setAttributeValue("ou", "testpeople");
        template.bind("ou=testpeople", ctx, null);

        ctx.setAttributeValue("ou", "testgroups");
        template.bind("ou=testgroups", ctx, null);

        DirContextAdapter group = new DirContextAdapter();

        group.setAttributeValue("objectclass", "groupOfNames");
        group.setAttributeValue("cn", "clowns");
        group.setAttributeValue("member", "cn=nobody,ou=testpeople,dc=acegisecurity,dc=org");
        template.bind("cn=clowns,ou=testgroups", group, null);

        group.setAttributeValue("cn", "acrobats");
        template.bind("cn=acrobats,ou=testgroups", group, null);

        mgr.setUserDnBase("ou=testpeople");
        mgr.setGroupSearchBase("ou=testgroups");
        mgr.setGroupRoleAttributeName("cn");
        mgr.setGroupMemberAttributeName("member");
        mgr.setUserDetailsMapper(new PersonContextMapper());
    }


    protected void onTearDown() throws Exception {
//        Iterator people = template.list("ou=testpeople").iterator();

//        DirContext rootCtx = new DirContextAdapter(new DistinguishedName(getInitialCtxFactory().getRootDn()));
//
//        while(people.hasNext()) {
//            template.unbind((String) people.next() + ",ou=testpeople");
//        }

        template.unbind("ou=testpeople",true);
        template.unbind("ou=testgroups",true);

        SecurityContextHolder.clearContext();
        super.onTearDown();
    }

    public void testLoadUserByUsernameReturnsCorrectData() {
        mgr.setUserDnBase("ou=people");
        mgr.setGroupSearchBase("ou=groups");
        UserDetails bob = mgr.loadUserByUsername("bob");
        assertEquals("bob", bob.getUsername());
        // password isn't read
        //assertEquals("bobspassword", bob.getPassword());

        assertEquals(1, bob.getAuthorities().length);
    }

    public void testLoadingInvalidUsernameThrowsUsernameNotFoundException() {

        try {
            mgr.loadUserByUsername("jim");
            fail("Expected UsernameNotFoundException for user 'jim'");
        } catch(UsernameNotFoundException expected) {
            // expected
        }
    }

    public void testUserExistsReturnsTrueForValidUser() {
        mgr.setUserDnBase("ou=people");
        assertTrue(mgr.userExists("bob"));
    }

    public void testUserExistsReturnsFalseForInValidUser() {
        assertFalse(mgr.userExists("jim"));
    }

    public void testCreateNewUserSucceeds() {
        InetOrgPerson.Essence p = new InetOrgPerson.Essence();
        p.setCn(new String[] {"Joe Smeth"});
        p.setSn("Smeth");
        p.setUid("joe");
        p.setAuthorities(TEST_AUTHORITIES);

        mgr.createUser(p.createUserDetails());
    }

    public void testDeleteUserSucceeds() {
        InetOrgPerson.Essence p = new InetOrgPerson.Essence();
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
        assertEquals(0, mgr.getUserAuthorities(mgr.buildDn("don"), "don").length);
    }

    public void testPasswordChangeWithCorrectOldPasswordSucceeds() {
        InetOrgPerson.Essence p = new InetOrgPerson.Essence();
        p.setCn(new String[] {"John Yossarian"});
        p.setSn("Yossarian");
        p.setUid("johnyossarian");
        p.setPassword("yossarianspassword");
        p.setAuthorities(TEST_AUTHORITIES);

        mgr.createUser(p.createUserDetails());

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("johnyossarian", "yossarianspassword", TEST_AUTHORITIES));

        mgr.changePassword("yossarianspassword", "yossariansnewpassword");

        assertTrue(template.compare("uid=johnyossarian,ou=testpeople,dc=acegisecurity,dc=org",
                "userPassword", "yossariansnewpassword"));
    }

    public void testPasswordChangeWithWrongOldPasswordFails() {
        InetOrgPerson.Essence p = new InetOrgPerson.Essence();
        p.setCn(new String[] {"John Yossarian"});
        p.setSn("Yossarian");
        p.setUid("johnyossarian");
        p.setPassword("yossarianspassword");
        p.setAuthorities(TEST_AUTHORITIES);

        mgr.createUser(p.createUserDetails());

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("johnyossarian", "yossarianspassword", TEST_AUTHORITIES));

        try {
            mgr.changePassword("wrongpassword", "yossariansnewpassword");
            fail("Expected BadCredentialsException");
        } catch (BadCredentialsException expected) {
        }

    }
}
