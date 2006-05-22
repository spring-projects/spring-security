package org.acegisecurity.ldap.search;

import org.acegisecurity.ldap.AbstractLdapServerTestCase;
import org.acegisecurity.ldap.DefaultInitialDirContextFactory;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

/**
 * Tests for FilterBasedLdapUserSearch.
 * 
 * @author Luke Taylor
 * @version $Id$
 */
public class FilterBasedLdapUserSearchTests extends AbstractLdapServerTestCase {
    private DefaultInitialDirContextFactory dirCtxFactory;

    public void onSetUp() {
        dirCtxFactory = getInitialCtxFactory();
        dirCtxFactory.setManagerDn(MANAGER_USER);
        dirCtxFactory.setManagerPassword(MANAGER_PASSWORD);
    }

    public FilterBasedLdapUserSearchTests(String string) {
        super(string);
    }

    public FilterBasedLdapUserSearchTests() {
        super();
    }

    public void testBasicSearch() {
        FilterBasedLdapUserSearch locator =
                new FilterBasedLdapUserSearch("ou=people", "(uid={0})", dirCtxFactory);
        locator.setSearchSubtree(false);
        locator.setSearchTimeLimit(0);
        locator.setDerefLinkFlag(false);

        LdapUserDetails bob = locator.searchForUser("bob");
        assertEquals("bob", bob.getUsername());
        // name is wrong with embedded apacheDS
//        assertEquals("uid=bob,ou=people,dc=acegisecurity,dc=org", bob.getDn());
    }

    public void testSubTreeSearchSucceeds() {
        // Don't set the searchBase, so search from the root.
        FilterBasedLdapUserSearch locator =
                new FilterBasedLdapUserSearch("", "(cn={0})", dirCtxFactory);
        locator.setSearchSubtree(true);

        LdapUserDetails ben = locator.searchForUser("Ben Alex");
        assertEquals("Ben Alex", ben.getUsername());
//        assertEquals("uid=ben,ou=people,dc=acegisecurity,dc=org", ben.getDn());
    }

    public void testSearchForInvalidUserFails() {
        FilterBasedLdapUserSearch locator =
                new FilterBasedLdapUserSearch("ou=people", "(uid={0})", dirCtxFactory);

        try {
            locator.searchForUser("Joe");
            fail("Expected UsernameNotFoundException for non-existent user.");
        } catch (UsernameNotFoundException expected) {
        }
    }

    public void testFailsOnMultipleMatches() {
        FilterBasedLdapUserSearch locator =
                new FilterBasedLdapUserSearch("ou=people", "(cn=*)", dirCtxFactory);

        try {
            locator.searchForUser("Ignored");
            fail("Expected exception for multiple search matches.");
        } catch (IncorrectResultSizeDataAccessException expected) {
        }
    }

    // Try some funny business with filters.

    public void testExtraFilterPartToExcludeBob() throws Exception {
        FilterBasedLdapUserSearch locator =
                new FilterBasedLdapUserSearch("ou=people",
                        "(&(cn=*)(!(|(uid={0})(uid=marissa))))",
                        dirCtxFactory);

        // Search for bob, get back ben...
        LdapUserDetails ben = locator.searchForUser("bob");
        String cn = (String)ben.getAttributes().get("cn").get();
        assertEquals("Ben Alex", cn);
//        assertEquals("uid=ben,ou=people,"+ROOT_DN, ben.getDn());
    }
}
