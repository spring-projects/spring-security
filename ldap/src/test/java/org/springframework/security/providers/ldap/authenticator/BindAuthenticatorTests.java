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

package org.springframework.security.providers.ldap.authenticator;

import org.springframework.security.Authentication;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.security.ldap.AbstractLdapIntegrationTests;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import org.junit.Test;

/**
 * Tests for {@link BindAuthenticator}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class BindAuthenticatorTests extends AbstractLdapIntegrationTests {
    //~ Instance fields ================================================================================================

    private BindAuthenticator authenticator;
    private Authentication bob;
//    private Authentication ben;


    //~ Methods ========================================================================================================

    public void onSetUp() {
        authenticator = new BindAuthenticator(getContextSource());
        authenticator.setMessageSource(new SpringSecurityMessageSource());
        bob = new UsernamePasswordAuthenticationToken("bob", "bobspassword");
//        ben = new UsernamePasswordAuthenticationToken("ben", "benspassword");

    }

    @Test
    public void testAuthenticationWithCorrectPasswordSucceeds() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        DirContextOperations user = authenticator.authenticate(bob);
        assertEquals("bob", user.getStringAttribute("uid"));
    }

    @Test
    public void testAuthenticationWithInvalidUserNameFails() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        try {
            authenticator.authenticate(new UsernamePasswordAuthenticationToken("nonexistentsuser", "password"));
            fail("Shouldn't be able to bind with invalid username");
        } catch (BadCredentialsException expected) {}
    }

    @Test
    public void testAuthenticationWithUserSearch() throws Exception {
        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=bob,ou=people"));

        authenticator.setUserSearch(new MockUserSearch(ctx));
        authenticator.afterPropertiesSet();
        authenticator.authenticate(bob);
    }

    @Test
    public void testAuthenticationWithWrongPasswordFails() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        try {
            authenticator.authenticate(new UsernamePasswordAuthenticationToken("bob", "wrongpassword"));
            fail("Shouldn't be able to bind with wrong password");
        } catch (BadCredentialsException expected) {}
    }

    @Test
    public void testUserDnPatternReturnsCorrectDn() {
        authenticator.setUserDnPatterns(new String[] {"cn={0},ou=people"});
        assertEquals("cn=Joe,ou=people", authenticator.getUserDns("Joe").get(0));
    }
}
