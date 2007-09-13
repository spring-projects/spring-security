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

package org.acegisecurity.ldap.search;

import org.acegisecurity.ldap.DefaultInitialDirContextFactory;
import org.acegisecurity.ldap.AbstractLdapIntegrationTests;

import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;

import org.springframework.dao.IncorrectResultSizeDataAccessException;


/**
 * Tests for FilterBasedLdapUserSearch.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class FilterBasedLdapUserSearchTests extends AbstractLdapIntegrationTests {
    //~ Instance fields ================================================================================================

    private DefaultInitialDirContextFactory dirCtxFactory;

    //~ Methods ========================================================================================================

    public void onSetUp() throws Exception {
        super.onSetUp();
        dirCtxFactory = (DefaultInitialDirContextFactory) getContextSource();
    }

    public void testBasicSearch() {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people", "(uid={0})", dirCtxFactory);
        locator.setSearchSubtree(false);
        locator.setSearchTimeLimit(0);
        locator.setDerefLinkFlag(false);

        LdapUserDetails bob = locator.searchForUser("bob");
        assertEquals("bob", bob.getUsername());

        // name is wrong with embedded apacheDS
//        assertEquals("uid=bob,ou=people,dc=acegisecurity,dc=org", bob.getDn());
    }

    // Try some funny business with filters.
    public void testExtraFilterPartToExcludeBob() throws Exception {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people",
                "(&(cn=*)(!(|(uid={0})(uid=marissa))))", dirCtxFactory);

        // Search for bob, get back ben...
        LdapUserDetails ben = locator.searchForUser("bob");
        String cn = (String) ben.getAttributes().get("cn").get();
        assertEquals("Ben Alex", cn);

//        assertEquals("uid=ben,ou=people,"+ROOT_DN, ben.getDn());
    }

    public void testFailsOnMultipleMatches() {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people", "(cn=*)", dirCtxFactory);

        try {
            locator.searchForUser("Ignored");
            fail("Expected exception for multiple search matches.");
        } catch (IncorrectResultSizeDataAccessException expected) {}
    }

    public void testSearchForInvalidUserFails() {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people", "(uid={0})", dirCtxFactory);

        try {
            locator.searchForUser("Joe");
            fail("Expected UsernameNotFoundException for non-existent user.");
        } catch (UsernameNotFoundException expected) {}
    }

    public void testSubTreeSearchSucceeds() {
        // Don't set the searchBase, so search from the root.
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("", "(cn={0})", dirCtxFactory);
        locator.setSearchSubtree(true);

        LdapUserDetails ben = locator.searchForUser("Ben Alex");
        assertEquals("ben", ben.getUsername());

//        assertEquals("uid=ben,ou=people,dc=acegisecurity,dc=org", ben.getDn());
    }

    // TODO: Add test with non-uid username
}
