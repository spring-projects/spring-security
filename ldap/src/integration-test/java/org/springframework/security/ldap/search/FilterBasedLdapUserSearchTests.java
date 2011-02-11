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

import static org.junit.Assert.*;

import org.junit.*;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.AbstractLdapIntegrationTests;

/**
 * Tests for FilterBasedLdapUserSearch.
 *
 * @author Luke Taylor
 */
public class FilterBasedLdapUserSearchTests extends AbstractLdapIntegrationTests {

    @Test
    public void basicSearchSucceeds() {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people", "(uid={0})", getContextSource());
        locator.setSearchSubtree(false);
        locator.setSearchTimeLimit(0);
        locator.setDerefLinkFlag(false);

        DirContextOperations bob = locator.searchForUser("bob");
        assertEquals("bob", bob.getStringAttribute("uid"));

        assertEquals(new DistinguishedName("uid=bob,ou=people"), bob.getDn());
    }

    @Test
    public void searchForNameWithCommaSucceeds() {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people", "(uid={0})", getContextSource());
        locator.setSearchSubtree(false);

        DirContextOperations jerry = locator.searchForUser("jerry");
        assertEquals("jerry", jerry.getStringAttribute("uid"));

        assertEquals(new DistinguishedName("cn=mouse\\, jerry,ou=people"), jerry.getDn());
    }

    // Try some funny business with filters.
    @Test
    public void extraFilterPartToExcludeBob() throws Exception {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people",
                "(&(cn=*)(!(|(uid={0})(uid=rod)(uid=jerry)(uid=slashguy))))", getContextSource());

        // Search for bob, get back ben...
        DirContextOperations ben = locator.searchForUser("bob");
        assertEquals("Ben Alex", ben.getStringAttribute("cn"));
    }

    @Test(expected=IncorrectResultSizeDataAccessException.class)
    public void searchFailsOnMultipleMatches() {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people", "(cn=*)", getContextSource());
        locator.searchForUser("Ignored");
    }

    @Test(expected=UsernameNotFoundException.class)
    public void searchForInvalidUserFails() {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=people", "(uid={0})", getContextSource());
        locator.searchForUser("Joe");
    }

    @Test
    public void subTreeSearchSucceeds() {
        // Don't set the searchBase, so search from the root.
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("", "(cn={0})", getContextSource());
        locator.setSearchSubtree(true);

        DirContextOperations ben = locator.searchForUser("Ben Alex");
        assertEquals("ben", ben.getStringAttribute("uid"));

        assertEquals(new DistinguishedName("uid=ben,ou=people"), ben.getDn());
    }

    @Test
    public void searchWithDifferentSearchBaseIsSuccessful() throws Exception {
        FilterBasedLdapUserSearch locator = new FilterBasedLdapUserSearch("ou=otherpeople", "(cn={0})", getContextSource());
        DirContextOperations joe = locator.searchForUser("Joe Smeth");
        assertEquals("Joe Smeth", joe.getStringAttribute("cn"));
    }

}
