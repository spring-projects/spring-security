/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

import org.acegisecurity.providers.ldap.*;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.BadCredentialsException;
import org.springframework.util.Assert;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.directory.DirContext;
import javax.naming.NamingException;
import javax.naming.NamingEnumeration;

/**
 * LdapUserSearch implementation which uses an Ldap filter to locate the user.
 *
 * @author Robert Sanders
 * @author Luke Taylor
 * @version $Id$
 */
public class FilterBasedLdapUserSearch implements LdapUserSearch {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(FilterBasedLdapUserSearch.class);

    //~ Instance fields ========================================================

    /**
     * Context name to search in, relative to the root DN of the configured
     * InitialDirContextFactory.
     */
    private String searchBase = "";

    /**
     * If true then searches the entire subtree as identified by context,
     * if false (the default) then only searches the level identified by the context.
     */
//    private boolean searchSubtree = false;

    private int searchScope = SearchControls.ONELEVEL_SCOPE;

    /**
     * The filter expression used in the user search. This is an LDAP
     * search filter (as defined in 'RFC 2254') with optional arguments. See the documentation
     * for the <tt>search</tt> methods in {@link javax.naming.directory.DirContext DirContext}
     * for more information.
     * <p>
     * In this case, the username is the only parameter.
     * </p>
     * Possible examples are:
     * <ul>
     * <li>(uid={0}) - this would search for a username match on the uid attribute.</li>
     * </ul>
     * TODO: more examples.
     *
     */
    private String searchFilter;

    /**
     * The time (in milliseconds) which to wait before the search fails;
     * the default is zero, meaning forever.
     */
    private int searchTimeLimit = 0;

    private InitialDirContextFactory initialDirContextFactory;

    //~ Methods ================================================================

    /**
     * Return the LdapUserInfo containing the user's information, or null if
     * no SearchResult is found.
     *
     * @param username the username to search for.
     */
    public LdapUserInfo searchForUser(String username) {
        DirContext ctx = initialDirContextFactory.newInitialDirContext();
        SearchControls ctls = new SearchControls();
        ctls.setTimeLimit( searchTimeLimit );
        ctls.setSearchScope( searchScope );

        try {
            String[] args = new String[] { LdapUtils.escapeNameForFilter(username) };

            NamingEnumeration results = ctx.search(searchBase, searchFilter, args, ctls);

            if (!results.hasMore()) {
                throw new UsernameNotFoundException("User " + username + " not found in directory.");
            }

            SearchResult searchResult = (SearchResult)results.next();

            if(results.hasMore()) {
               throw new BadCredentialsException("Expected a single user but search returned multiple results");
            }

            StringBuffer userDn = new StringBuffer(searchResult.getName());

            if(searchBase.length() > 0) {
                userDn.append(",");
                userDn.append(searchBase);
            }

            userDn.append(",");
            userDn.append(ctx.getNameInNamespace());

            return new LdapUserInfo(userDn.toString(), searchResult.getAttributes());

        } catch(NamingException ne) {
            throw new LdapDataAccessException("User Couldn't be found due to exception", ne);
        } finally {
            LdapUtils.closeContext(ctx);
        }
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(initialDirContextFactory, "initialDirContextFactory must be set");
        Assert.notNull(searchFilter, "searchFilter must be set.");

        if(searchBase.equals("")) {
            logger.info("No search base DN supplied. Search will be performed from the root: " +
                    initialDirContextFactory.getRootDn());
        }
    }

    public void setInitialDirContextFactory(InitialDirContextFactory initialDirContextFactory) {
        this.initialDirContextFactory = initialDirContextFactory;
    }

    public void setSearchFilter(String searchFilter) {
        this.searchFilter = searchFilter;
    }

    public void setSearchSubtree(boolean searchSubtree) {
//        this.searchSubtree = searchSubtree;
        this.searchScope = searchSubtree ?
                SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE;
    }

    public void setSearchTimeLimit(int searchTimeLimit) {
        this.searchTimeLimit = searchTimeLimit;
    }

    public void setSearchBase(String searchBase) {
        this.searchBase = searchBase;
    }
}
