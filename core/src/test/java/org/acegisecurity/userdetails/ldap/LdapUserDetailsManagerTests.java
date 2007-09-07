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
package org.acegisecurity.userdetails.ldap;

import org.acegisecurity.ldap.AbstractLdapServerTestCase;
import org.acegisecurity.ldap.LdapUtils;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.springframework.ldap.LdapTemplate;
import org.springframework.ldap.support.DirContextAdapter;
import org.springframework.ldap.support.DistinguishedName;
import org.springframework.dao.DataAccessException;

import javax.naming.directory.DirContext;
import java.util.List;
import java.util.Iterator;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetailsManagerTests extends AbstractLdapServerTestCase {
    private static final GrantedAuthority[] TEST_AUTHORITIES = new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_CLOWNS"),
                new GrantedAuthorityImpl("ROLE_ACROBATS")};
    private LdapUserDetailsManager mgr;
    private LdapTemplate template;

    protected void onSetUp() {
        mgr = new LdapUserDetailsManager(getInitialCtxFactory());
        template = new LdapTemplate(getInitialCtxFactory());
        DirContextAdapter ctx = new DirContextAdapter();

        ctx.setAttributeValue("objectclass", "organizationalUnit");
        ctx.setAttributeValue("ou", "testpeople");
        template.bind("ou=testpeople", ctx, null);

        ctx.setAttributeValue("ou", "testgroups");
        template.bind("ou=testgroups", ctx, null);

        DirContextAdapter group = new DirContextAdapter();

        group.setAttributeValue("objectclass", "groupOfNames");
        group.setAttributeValue("cn", "clowns");
        template.bind("cn=clowns,ou=testgroups", ctx, null);

        group.setAttributeValue("cn", "acrobats");
        template.bind("cn=acrobats,ou=testgroups", ctx, null);

        mgr.setUserDnBase("ou=testpeople");
        mgr.setGroupSearchBase("ou=testgroups");
        mgr.setGroupRoleAttributeName("cn");
        mgr.setGroupMemberAttributeName("member");
        mgr.setUserDetailsMapper(new PersonContextMapper());
    }


    protected void tearDown() throws Exception {
        Iterator people = template.list("ou=testpeople").iterator();

        DirContext rootCtx = new DirContextAdapter(new DistinguishedName(getInitialCtxFactory().getRootDn()));

        while(people.hasNext()) {
            template.unbind(LdapUtils.getRelativeName((String) people.next(), rootCtx));
        }

        template.unbind("ou=testpeople");
        template.unbind("cn=acrobats,ou=testgroups");
        template.unbind("cn=clowns,ou=testgroups");
        template.unbind("ou=testgroups");

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
}
