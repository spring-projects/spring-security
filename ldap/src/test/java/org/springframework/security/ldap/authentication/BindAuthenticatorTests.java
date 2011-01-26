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

package org.springframework.security.ldap.authentication;

import static org.junit.Assert.*;

import org.junit.*;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.ldap.AbstractLdapIntegrationTests;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;

/**
 * Tests for {@link BindAuthenticator}.
 *
 * @author Luke Taylor
 */
public class BindAuthenticatorTests extends AbstractLdapIntegrationTests {
    //~ Instance fields ================================================================================================

    private BindAuthenticator authenticator;
    private Authentication bob;


    //~ Methods ========================================================================================================

    public void onSetUp() {
        authenticator = new BindAuthenticator(getContextSource());
        authenticator.setMessageSource(new SpringSecurityMessageSource());
        bob = new UsernamePasswordAuthenticationToken("bob", "bobspassword");

    }

    @Test(expected=BadCredentialsException.class)
    public void emptyPasswordIsRejected() {
        authenticator.authenticate(new UsernamePasswordAuthenticationToken("jen", ""));
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
        //DirContextAdapter ctx = new DirContextAdapter(new DistinguishedName("uid=bob,ou=people"));
        authenticator.setUserSearch(new FilterBasedLdapUserSearch("ou=people", "(uid={0})", getContextSource()));
        authenticator.afterPropertiesSet();
        authenticator.authenticate(bob);
        // SEC-1444
        authenticator.setUserSearch(new FilterBasedLdapUserSearch("ou=people", "(cn={0})", getContextSource()));
        authenticator.authenticate(new UsernamePasswordAuthenticationToken("mouse, jerry", "jerryspassword"));
        authenticator.authenticate(new UsernamePasswordAuthenticationToken("slash/guy", "slashguyspassword"));
        // SEC-1661
        authenticator.setUserSearch(new FilterBasedLdapUserSearch("ou=\\\"quoted people\\\"", "(cn={0})", getContextSource()));
        authenticator.authenticate(new UsernamePasswordAuthenticationToken("quoteguy", "quoteguyspassword"));
    }
/*
    @Test
    public void messingWithEscapedChars() throws Exception {
        Hashtable<String,String> env = new Hashtable<String,String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://127.0.0.1:22389/dc=springsource,dc=com");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=springsource,dc=com");
        env.put(Context.SECURITY_CREDENTIALS, "password");

        InitialDirContext idc = new InitialDirContext(env);
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        DistinguishedName baseDn = new DistinguishedName("ou=\\\"quoted people\\\"");
        NamingEnumeration<SearchResult> matches = idc.search(baseDn, "(cn=*)", new Object[] {"quoteguy"}, searchControls);

        while(matches.hasMore()) {
            SearchResult match = matches.next();
            DistinguishedName dn = new DistinguishedName(match.getName());
            System.out.println("**** Match: " + match.getName() + " ***** " + dn);

        }
    }
*/
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
