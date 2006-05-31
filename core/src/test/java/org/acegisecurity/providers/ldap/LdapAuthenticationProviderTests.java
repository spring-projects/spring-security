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

package org.acegisecurity.providers.ldap;

import junit.framework.TestCase;

import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;

import java.util.ArrayList;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;


/**
 * Tests {@link LdapAuthenticationProvider}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapAuthenticationProviderTests extends TestCase {
    //~ Constructors ===================================================================================================

    public LdapAuthenticationProviderTests(String string) {
        super(string);
    }

    public LdapAuthenticationProviderTests() {
        super();
    }

    //~ Methods ========================================================================================================

    public void testDifferentCacheValueCausesException() {
        LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
                new MockAuthoritiesPopulator());
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken("bob", "bobspassword");

        // User is authenticated here
        UserDetails user = ldapProvider.retrieveUser("bob", authRequest);
        // Assume the user details object is cached...

        // And a subsequent authentication request comes in on the cached data
        authRequest = new UsernamePasswordAuthenticationToken("bob", "wrongpassword");

        try {
            ldapProvider.additionalAuthenticationChecks(user, authRequest);
            fail("Expected BadCredentialsException should have failed with wrong password");
        } catch (BadCredentialsException expected) {}
    }

    public void testEmptyOrNullUserNameThrowsException() {
        LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
                new MockAuthoritiesPopulator());

        try {
            ldapProvider.retrieveUser("", new UsernamePasswordAuthenticationToken("bob", "bobspassword"));
            fail("Expected BadCredentialsException for empty username");
        } catch (BadCredentialsException expected) {}

        try {
            ldapProvider.retrieveUser(null, new UsernamePasswordAuthenticationToken("bob", "bobspassword"));
            fail("Expected BadCredentialsException for null username");
        } catch (BadCredentialsException expected) {}
    }

    public void testEmptyPasswordIsRejected() {
        LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
                new MockAuthoritiesPopulator());
        try {
            ldapProvider.retrieveUser("jen", new UsernamePasswordAuthenticationToken("jen", ""));
            fail("Expected BadCredentialsException for empty password");
        } catch (BadCredentialsException expected) {}
    }

    public void testNormalUsage() {
        LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
                new MockAuthoritiesPopulator());

        assertNotNull(ldapProvider.getAuthoritiesPoulator());

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken("bob", "bobspassword");
        UserDetails user = ldapProvider.retrieveUser("bob", authRequest);
        assertEquals(2, user.getAuthorities().length);
        assertEquals("bobspassword", user.getPassword());
        assertEquals("bob", user.getUsername());

        ArrayList authorities = new ArrayList();
        authorities.add(user.getAuthorities()[0].getAuthority());
        authorities.add(user.getAuthorities()[1].getAuthority());

        assertTrue(authorities.contains("ROLE_FROM_ENTRY"));
        assertTrue(authorities.contains("ROLE_FROM_POPULATOR"));

        ldapProvider.additionalAuthenticationChecks(user, authRequest);
    }

    //~ Inner Classes ==================================================================================================

    class MockAuthenticator implements LdapAuthenticator {
        Attributes userAttributes = new BasicAttributes("cn", "bob");

        public LdapUserDetails authenticate(String username, String password) {
            LdapUserDetailsImpl.Essence userEssence = new LdapUserDetailsImpl.Essence();
            userEssence.setPassword("{SHA}anencodedpassword");
            userEssence.setAttributes(userAttributes);

            if (username.equals("bob") && password.equals("bobspassword")) {
                userEssence.setDn("cn=bob,ou=people,dc=acegisecurity,dc=org");
                userEssence.addAuthority(new GrantedAuthorityImpl("ROLE_FROM_ENTRY"));

                return userEssence.createUserDetails();
            } else if (username.equals("jen") && password.equals("")) {
                userEssence.setDn("cn=jen,ou=people,dc=acegisecurity,dc=org");
                userEssence.addAuthority(new GrantedAuthorityImpl("ROLE_FROM_ENTRY"));

                return userEssence.createUserDetails();
            }

            throw new BadCredentialsException("Authentication failed.");
        }
    }

// This test kills apacheDS in embedded mode because the search returns an invalid DN
//    public void testIntegration() throws Exception {
//        BindAuthenticator authenticator = new BindAuthenticator(getInitialCtxFactory());
//        //PasswordComparisonAuthenticator authenticator = new PasswordComparisonAuthenticator();
//        //authenticator.setUserDnPatterns("cn={0},ou=people");
//
//        FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch("ou=people", "(cn={0})", getInitialCtxFactory());
//
//        authenticator.setUserSearch(userSearch);
//        authenticator.afterPropertiesSet();
//
//        DefaultLdapAuthoritiesPopulator populator;
//        populator = new DefaultLdapAuthoritiesPopulator(getInitialCtxFactory(), "ou=groups");
//        populator.setRolePrefix("ROLE_");
//
//        LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(authenticator, populator);
//
//        Authentication auth = ldapProvider.authenticate(new UsernamePasswordAuthenticationToken("Ben Alex","benspassword"));
//        assertEquals(2, auth.getAuthorities().length);
//    }
    class MockAuthoritiesPopulator implements LdapAuthoritiesPopulator {
        public GrantedAuthority[] getGrantedAuthorities(LdapUserDetails userDetailsll) {
            return new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_FROM_POPULATOR")};
        }
    }
}
