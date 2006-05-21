package org.acegisecurity.providers.ldap;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.ldap.*;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;

import java.util.ArrayList;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapAuthenticationProviderTests extends AbstractLdapServerTestCase {

    public LdapAuthenticationProviderTests(String string) {
        super(string);
    }

    public LdapAuthenticationProviderTests() {
        super();
    }

    public void testNormalUsage() {
        LdapAuthenticationProvider ldapProvider
                = new LdapAuthenticationProvider(new MockAuthenticator(), new MockAuthoritiesPopulator());

        assertNotNull(ldapProvider.getAuthoritiesPoulator());

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("bob","bobspassword");
        UserDetails user = ldapProvider.retrieveUser("bob", token);
        assertEquals(2, user.getAuthorities().length);

        ArrayList authorities = new ArrayList();
        authorities.add(user.getAuthorities()[0].getAuthority());
        authorities.add(user.getAuthorities()[1].getAuthority());

        assertTrue(authorities.contains("ROLE_FROM_ENTRY"));
        assertTrue(authorities.contains("ROLE_FROM_POPULATOR"));

        ldapProvider.additionalAuthenticationChecks(user, token);
    }

    public void testEmptyOrNullUserNameThrowsException() {
        LdapAuthenticationProvider ldapProvider
                = new LdapAuthenticationProvider(new MockAuthenticator(), new MockAuthoritiesPopulator());

        try {
            ldapProvider.retrieveUser("", new UsernamePasswordAuthenticationToken("bob","bobspassword"));
            fail("Expected BadCredentialsException for empty username");
        } catch(BadCredentialsException expected) {
        }

        try {
            ldapProvider.retrieveUser(null, new UsernamePasswordAuthenticationToken("bob","bobspassword"));
            fail("Expected BadCredentialsException for null username");
        } catch(BadCredentialsException expected) {
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
           return new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_FROM_POPULATOR") };
        }
    }

    class MockAuthenticator implements LdapAuthenticator {
        Attributes userAttributes = new BasicAttributes("cn","bob");

        public LdapUserDetails authenticate(String username, String password) {
            if(username.equals("bob") && password.equals("bobspassword")) {
                LdapUserDetailsImpl.Essence userEssence = new LdapUserDetailsImpl.Essence();
                userEssence.setDn("cn=bob,ou=people,dc=acegisecurity,dc=org");
                userEssence.setAttributes(userAttributes);
                userEssence.addAuthority(new GrantedAuthorityImpl("ROLE_FROM_ENTRY"));
                return userEssence.createUserDetails();
            }
            throw new BadCredentialsException("Authentication of Bob failed.");
        }
    }
}
