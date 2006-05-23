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

package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthorityImpl;

import org.acegisecurity.ldap.AbstractLdapServerTestCase;

import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsMapper;


/**
 * Tests for {@link BindAuthenticator}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class BindAuthenticatorTests extends AbstractLdapServerTestCase {
    //~ Instance fields ================================================================================================

    private BindAuthenticator authenticator;

    //~ Methods ========================================================================================================

    public void onSetUp() {
        authenticator = new BindAuthenticator(getInitialCtxFactory());
        authenticator.setMessageSource(new AcegiMessageSource());
    }

    public void testAuthenticationWithCorrectPasswordSucceeds() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        LdapUserDetails user = authenticator.authenticate("bob", "bobspassword");
        assertEquals("bob", user.getUsername());
    }

    public void testAuthenticationWithInvalidUserNameFails() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        try {
            authenticator.authenticate("nonexistentsuser", "bobspassword");
            fail("Shouldn't be able to bind with invalid username");
        } catch (BadCredentialsException expected) {}
    }

    public void testAuthenticationWithUserSearch() throws Exception {
        LdapUserDetailsImpl.Essence userEssence = new LdapUserDetailsImpl.Essence();
        userEssence.setDn("uid=bob,ou=people,dc=acegisecurity,dc=org");

        authenticator.setUserSearch(new MockUserSearch(userEssence.createUserDetails()));
        authenticator.afterPropertiesSet();
        authenticator.authenticate("bob", "bobspassword");
    }

    public void testAuthenticationWithWrongPasswordFails() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        try {
            authenticator.authenticate("bob", "wrongpassword");
            fail("Shouldn't be able to bind with wrong password");
        } catch (BadCredentialsException expected) {}
    }

    // TODO: Create separate tests for base class
    public void testRoleRetrieval() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        LdapUserDetailsMapper userMapper = new LdapUserDetailsMapper();
        userMapper.setRoleAttributes(new String[] {"uid"});

        authenticator.setUserDetailsMapper(userMapper);

        LdapUserDetails user = authenticator.authenticate("bob", "bobspassword");

        assertEquals(1, user.getAuthorities().length);
        assertEquals(new GrantedAuthorityImpl("ROLE_BOB"), user.getAuthorities()[0]);
    }

    public void testUserDnPatternReturnsCorrectDn() {
        authenticator.setUserDnPatterns(new String[] {"cn={0},ou=people"});
        assertEquals("cn=Joe,ou=people," + getInitialCtxFactory().getRootDn(), authenticator.getUserDns("Joe").get(0));
    }
}
