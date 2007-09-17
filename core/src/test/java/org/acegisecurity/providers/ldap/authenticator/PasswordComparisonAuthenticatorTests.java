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

import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.Authentication;

import org.acegisecurity.ldap.AbstractLdapIntegrationTests;
import org.acegisecurity.ldap.InitialDirContextFactory;

import org.acegisecurity.providers.encoding.PlaintextPasswordEncoder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.DirContextOperations;


/**
 * Tests for {@link PasswordComparisonAuthenticator}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class PasswordComparisonAuthenticatorTests extends AbstractLdapIntegrationTests {
    //~ Instance fields ================================================================================================

    private PasswordComparisonAuthenticator authenticator;
    private Authentication bob;
    private Authentication ben;

    //~ Methods ========================================================================================================

    public void onSetUp() throws Exception {
        super.onSetUp();
        authenticator = new PasswordComparisonAuthenticator((InitialDirContextFactory) getContextSource());
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});
        bob = new UsernamePasswordAuthenticationToken("bob", "bobspassword");
        ben = new UsernamePasswordAuthenticationToken("ben", "benspassword");
    }

    public void onTearDown() throws Exception {
        super.onTearDown();
        // com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
    }

    public void testAllAttributesAreRetrievedByDefault() {
        DirContextAdapter user = (DirContextAdapter) authenticator.authenticate(bob);
        //System.out.println(user.getAttributes().toString());
        assertEquals("User should have 5 attributes", 5, user.getAttributes().size());
    }

    public void testFailedSearchGivesUserNotFoundException() throws Exception {
        authenticator = new PasswordComparisonAuthenticator((InitialDirContextFactory) getContextSource());
        assertTrue("User DN matches shouldn't be available", authenticator.getUserDns("Bob").isEmpty());
        authenticator.setUserSearch(new MockUserSearch(null));
        authenticator.afterPropertiesSet();

        try {
            authenticator.authenticate(new UsernamePasswordAuthenticationToken("Joe", "pass"));
            fail("Expected exception on failed user search");
        } catch (UsernameNotFoundException expected) {}
    }

    public void testLocalComparisonSucceedsWithShaEncodedPassword() {
        // Ben's password is SHA encoded
        authenticator.authenticate(ben);
    }

    public void testLocalPasswordComparisonFailsWithWrongPassword() {
        try {
            authenticator.authenticate(new UsernamePasswordAuthenticationToken("bob", "wrongpass"));
            fail("Authentication should fail with wrong password.");
        } catch (BadCredentialsException expected) {}
    }


   public void testLdapPasswordCompareFailsWithWrongPassword() {
       // Don't retrieve the password
       authenticator.setUserAttributes(new String[] {"uid", "cn", "sn"});
       try {
           authenticator.authenticate(new UsernamePasswordAuthenticationToken("bob", "wrongpass"));
           fail("Authentication should fail with wrong password.");
       } catch(BadCredentialsException expected) {
       }
   }

    public void testLocalPasswordComparisonSucceedsWithCorrectPassword() {
        DirContextOperations user = authenticator.authenticate(bob);
        // check username is retrieved.
        assertEquals("bob", user.getStringAttribute("uid"));
        String password = new String((byte[])user.getObjectAttribute("userPassword"));
        assertEquals("bobspassword", password);
    }

    public void testMultipleDnPatternsWorkOk() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=nonexistent", "uid={0},ou=people"});
        authenticator.authenticate(bob);
    }

    public void testOnlySpecifiedAttributesAreRetrieved() throws Exception {
        authenticator.setUserAttributes(new String[] {"uid", "userPassword"});
        authenticator.setPasswordEncoder(new PlaintextPasswordEncoder());

        DirContextAdapter user = (DirContextAdapter) authenticator.authenticate(bob);
        assertEquals("Should have retrieved 2 attribute (uid, userPassword)", 2, user.getAttributes().size());
    }

   public void testLdapCompareSucceedsWithCorrectPassword() {
       // Don't retrieve the password
       authenticator.setUserAttributes(new String[] {"uid"});
       // Bob has a plaintext password.
       authenticator.setPasswordEncoder(new PlaintextPasswordEncoder());
       authenticator.authenticate(bob);
   }

   public void testLdapCompareSucceedsWithShaEncodedPassword() {
       // Don't retrieve the password
       authenticator.setUserAttributes(new String[] {"uid"});
       authenticator.authenticate(ben);
   }

    public void testPasswordEncoderCantBeNull() {
        try {
            authenticator.setPasswordEncoder(null);
            fail("Password encoder can't be null");
        } catch (IllegalArgumentException expected) {}
    }

    public void testUseOfDifferentPasswordAttributeSucceeds() {
        authenticator.setPasswordAttributeName("uid");
        authenticator.authenticate(new UsernamePasswordAuthenticationToken("bob", "bob"));
    }

   public void testLdapCompareWithDifferentPasswordAttributeSucceeds() {
       authenticator.setUserAttributes(new String[] {"uid"});
       authenticator.setPasswordEncoder(new PlaintextPasswordEncoder());
       authenticator.setPasswordAttributeName("cn");
       authenticator.authenticate(new UsernamePasswordAuthenticationToken("ben", "Ben Alex"));
   }

    public void testWithUserSearch() {
        authenticator = new PasswordComparisonAuthenticator((InitialDirContextFactory) getContextSource());
        assertTrue("User DN matches shouldn't be available", authenticator.getUserDns("Bob").isEmpty());

        DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=Bob,ou=people,dc=acegisecurity,dc=org"));
        ctx.setAttributeValue("userPassword", "bobspassword");

        authenticator.setUserSearch(new MockUserSearch(ctx));
        authenticator.authenticate(new UsernamePasswordAuthenticationToken("shouldntbeused", "bobspassword"));
    }
}
