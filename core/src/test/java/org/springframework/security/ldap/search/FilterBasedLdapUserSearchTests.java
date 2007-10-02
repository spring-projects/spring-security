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

package org.springframework.security.ldap.search;

import org.springframework.security.ldap.DefaultInitialDirContextFactory;
import org.springframework.security.ldap.AbstractLdapIntegrationTests;

import org.springframework.security.userdetails.UsernameNotFoundException;

import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.DirContextOperations;
import org.junit.Test;

import static org.junit.Assert.*;

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

    @Test
    public void testBasicSearch() {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people", "(uid={0})", dirCtxFactory);
        locator.setSearchSubtree(false);
        locator.setSearchTimeLimit(0);
        locator.setDerefLinkFlag(false);

        DirContextOperations bob = locator.searchForUser("bob");
        assertEquals("bob", bob.getStringAttribute("uid"));

        // name is wrong with embedded apacheDS
//        assertEquals("uid=bob,ou=people,dc=springframework,dc=org", bob.getDn());
    }

    // Try some funny business with filters.
    @Test
    public void testExtraFilterPartToExcludeBob() throws Exception {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people",
                "(&(cn=*)(!(|(uid={0})(uid=marissa))))", dirCtxFactory);

        // Search for bob, get back ben...
        DirContextOperations ben = locator.searchForUser("bob");
        assertEquals("Ben Alex", ben.getStringAttribute("cn"));

//        assertEquals("uid=ben,ou=people,"+ROOT_DN, ben.getDn());
    }

    @Test
    public void testFailsOnMultipleMatches() {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people", "(cn=*)", dirCtxFactory);

        try {
            locator.searchForUser("Ignored");
            fail("Expected exception for multiple search matches.");
        } catch (IncorrectResultSizeDataAccessException expected) {}
    }

    @Test
    public void testSearchForInvalidUserFails() {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people", "(uid={0})", dirCtxFactory);

        try {
            locator.searchForUser("Joe");
            fail("Expected UsernameNotFoundException for non-existent user.");
        } catch (UsernameNotFoundException expected) {}
    }

    @Test
    public void testSubTreeSearchSucceeds() {
        // Don't set the searchBase, so search from the root.
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("", "(cn={0})", dirCtxFactory);
        locator.setSearchSubtree(true);

        DirContextOperations ben = locator.searchForUser("Ben Alex");
        assertEquals("ben", ben.getStringAttribute("uid"));

//        assertEquals("uid=ben,ou=people,dc=springframework,dc=org", ben.getDn());
    }

    // TODO: Add test with non-uid username
}
