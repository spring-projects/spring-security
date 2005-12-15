package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.providers.ldap.AbstractLdapServerTestCase;
import org.acegisecurity.providers.ldap.DefaultInitialDirContextFactory;
import org.acegisecurity.providers.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.BadCredentialsException;

/**
 * Tests for FilterBasedLdapUserSearch.
 * 
 * @author Luke Taylor
 * @version $Id$
 */
public class FilterBasedLdapUserSearchTests extends AbstractLdapServerTestCase {
    private DefaultInitialDirContextFactory dirCtxFactory;
    private FilterBasedLdapUserSearch locator;

    public void setUp() throws Exception {
        dirCtxFactory = new DefaultInitialDirContextFactory();
        dirCtxFactory.setUrl(PROVIDER_URL);
        dirCtxFactory.setManagerDn(MANAGER_USER);
        dirCtxFactory.setManagerPassword(MANAGER_PASSWORD);
        dirCtxFactory.afterPropertiesSet();
        locator = new FilterBasedLdapUserSearch();
        locator.setSearchSubtree(false);
        locator.setSearchTimeLimit(0);
        locator.setInitialDirContextFactory(dirCtxFactory);
    }

    public FilterBasedLdapUserSearchTests(String string) {
        super(string);
    }

    public FilterBasedLdapUserSearchTests() {
        super();
    }

    public void testBasicSearch() throws Exception {
        locator.setSearchBase("ou=people");
        locator.setSearchFilter("(uid={0})");
        locator.afterPropertiesSet();
        LdapUserDetails bob = locator.searchForUser("Bob");
        assertEquals("uid=bob,ou=people,"+ROOT_DN, bob.getDn());
    }

    public void testSubTreeSearchSucceeds() throws Exception {
        // Don't set the searchBase, so search from the root.
        locator.setSearchFilter("(uid={0})");
        locator.setSearchSubtree(true);
        locator.afterPropertiesSet();
        LdapUserDetails bob = locator.searchForUser("Bob");
        assertEquals("uid=bob,ou=people,"+ROOT_DN, bob.getDn());
    }

    public void testSearchForInvalidUserFails() {
        locator.setSearchBase("ou=people");
        locator.setSearchFilter("(uid={0})");

        try {
            locator.searchForUser("Joe");
            fail("Expected UsernameNotFoundException for non-existent user.");
        } catch (UsernameNotFoundException expected) {
        }
    }

    public void testFailsOnMultipleMatches() {
        locator.setSearchBase("ou=people");
        locator.setSearchFilter("(cn=*)");

        try {
            locator.searchForUser("Ignored");
            fail("Expected exception for multiple search matches.");
        } catch (BadCredentialsException expected) {
        }
    }

    /** Try some funny business with filters. */
    public void testExtraFilterPartToExcludeBob() {
        locator.setSearchBase("ou=people");
        locator.setSearchFilter("(&(cn=*)(!(uid={0})))");

        // Search for bob, get back ben...
        LdapUserDetails ben = locator.searchForUser("bob");
        assertEquals("cn=Ben Alex,ou=people,"+ROOT_DN, ben.getDn());
    }
}
