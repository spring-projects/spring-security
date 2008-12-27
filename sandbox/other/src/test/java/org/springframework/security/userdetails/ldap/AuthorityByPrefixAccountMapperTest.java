/**
 *
 */
package org.springframework.security.userdetails.ldap;

import junit.framework.TestCase;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;

import java.util.*;

/**
 * @author Valery Tydykov
 *
 */
public class AuthorityByPrefixAccountMapperTest extends TestCase {
    AuthorityByPrefixAccountMapper mapper;

    /*
     * (non-Javadoc)
     *
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        mapper = new AuthorityByPrefixAccountMapper();
    }

    /*
     * (non-Javadoc)
     *
     * @see junit.framework.TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        mapper = null;
    }

    /**
     * Test method for
     * {@link org.springframework.security.userdetails.ldap.AuthorityByPrefixAccountMapper#map(org.springframework.security.userdetails.UserDetails)}.
     */
    public final void testNormalOperation() {
        String expectedAuthority = "prefix1_role1";
        GrantedAuthority[] authorities = { new GrantedAuthorityImpl(expectedAuthority),
                new GrantedAuthorityImpl("prefix1_role2") };
        UserDetails user = new User("username1", "password1", false, false, false, false, Arrays.asList(authorities));
        mapper.setAuthorityPrefix("prefix1_");
        String authority = mapper.map(user);

        assertEquals(expectedAuthority, authority);
    }

    /**
     * Test method for
     * {@link org.springframework.security.userdetails.ldap.AuthorityByPrefixAccountMapper#map(org.springframework.security.userdetails.UserDetails)}.
     */
    public final void testAuthorityNotFoundThrowsException() {
        String expectedAuthority = "prefix1_role1";
        GrantedAuthority[] authorities = { new GrantedAuthorityImpl(expectedAuthority) };
        UserDetails user = new User("username1", "password1", false, false, false, false, Arrays.asList(authorities));
        mapper.setAuthorityPrefix("NoMatchPrefix");

        try {
            mapper.map(user);
            fail("exception expected");
        } catch (AuthorityNotFoundException expected) {
        } catch (Exception unexpected) {
            fail("map throws unexpected exception");
        }
    }

    /**
     * Test method for
     * {@link org.springframework.security.userdetails.ldap.AuthorityByPrefixAccountMapper#afterPropertiesSet()}.
     */
    public final void testAfterPropertiesSet() {
        try {
            mapper.afterPropertiesSet();
            fail("exception expected");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("unexpected exception");
        }
    }

    public final void testEmptyPrefixThrowsException() {
        try {
            mapper.setAuthorityPrefix("");
            fail("expected exception");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("unexpected exception");
        }

        try {
            mapper.setAuthorityPrefix(null);
            fail("AfterPropertiesSet didn't throw expected exception");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("AfterPropertiesSet throws unexpected exception");
        }
    }
}
