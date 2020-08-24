/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ldap.search;

import javax.naming.directory.SearchControls;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.util.Assert;

/**
 * LdapUserSearch implementation which uses an Ldap filter to locate the user.
 *
 * @author Robert Sanders
 * @author Luke Taylor
 * @see SearchControls
 */
public class FilterBasedLdapUserSearch implements LdapUserSearch {

	private static final Log logger = LogFactory.getLog(FilterBasedLdapUserSearch.class);

	private final ContextSource contextSource;

	/**
	 * The LDAP SearchControls object used for the search. Shared between searches so
	 * shouldn't be modified once the bean has been configured.
	 */
	private final SearchControls searchControls = new SearchControls();

	/**
	 * Context name to search in, relative to the base of the configured ContextSource.
	 */
	private String searchBase = "";

	/**
	 * The filter expression used in the user search. This is an LDAP search filter (as
	 * defined in 'RFC 2254') with optional arguments. See the documentation for the
	 * <tt>search</tt> methods in {@link javax.naming.directory.DirContext DirContext} for
	 * more information.
	 *
	 * <p>
	 * In this case, the username is the only parameter.
	 * </p>
	 * Possible examples are:
	 * <ul>
	 * <li>(uid={0}) - this would search for a username match on the uid attribute.</li>
	 * </ul>
	 */
	private final String searchFilter;

	public FilterBasedLdapUserSearch(String searchBase, String searchFilter, BaseLdapPathContextSource contextSource) {
		Assert.notNull(contextSource, "contextSource must not be null");
		Assert.notNull(searchFilter, "searchFilter must not be null.");
		Assert.notNull(searchBase, "searchBase must not be null (an empty string is acceptable).");
		this.searchFilter = searchFilter;
		this.contextSource = contextSource;
		this.searchBase = searchBase;
		setSearchSubtree(true);
		if (searchBase.length() == 0) {
			logger.info(
					"SearchBase not set. Searches will be performed from the root: " + contextSource.getBaseLdapPath());
		}
	}

	/**
	 * Return the LdapUserDetails containing the user's information
	 * @param username the username to search for.
	 * @return An LdapUserDetails object containing the details of the located user's
	 * directory entry
	 * @throws UsernameNotFoundException if no matching entry is found.
	 */
	@Override
	public DirContextOperations searchForUser(String username) {
		logger.debug(LogMessage.of(() -> "Searching for user '" + username + "', with user search " + this));
		SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(this.contextSource);
		template.setSearchControls(this.searchControls);
		try {
			return template.searchForSingleEntry(this.searchBase, this.searchFilter, new String[] { username });
		}
		catch (IncorrectResultSizeDataAccessException ex) {
			if (ex.getActualSize() == 0) {
				throw new UsernameNotFoundException("User " + username + " not found in directory.");
			}
			// Search should never return multiple results if properly configured
			throw ex;
		}
	}

	/**
	 * Sets the corresponding property on the {@link SearchControls} instance used in the
	 * search.
	 * @param deref the derefLinkFlag value as defined in SearchControls..
	 */
	public void setDerefLinkFlag(boolean deref) {
		this.searchControls.setDerefLinkFlag(deref);
	}

	/**
	 * If true then searches the entire subtree as identified by context, if false (the
	 * default) then only searches the level identified by the context.
	 * @param searchSubtree true the underlying search controls should be set to
	 * SearchControls.SUBTREE_SCOPE rather than SearchControls.ONELEVEL_SCOPE.
	 */
	public void setSearchSubtree(boolean searchSubtree) {
		this.searchControls
				.setSearchScope(searchSubtree ? SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE);
	}

	/**
	 * The time to wait before the search fails; the default is zero, meaning forever.
	 * @param searchTimeLimit the time limit for the search (in milliseconds).
	 */
	public void setSearchTimeLimit(int searchTimeLimit) {
		this.searchControls.setTimeLimit(searchTimeLimit);
	}

	/**
	 * Specifies the attributes that will be returned as part of the search.
	 * <p>
	 * null indicates that all attributes will be returned. An empty array indicates no
	 * attributes are returned.
	 * @param attrs An array of attribute names identifying the attributes that will be
	 * returned. Can be null.
	 */
	public void setReturningAttributes(String[] attrs) {
		this.searchControls.setReturningAttributes(attrs);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("[ searchFilter: '").append(this.searchFilter).append("', ");
		sb.append("searchBase: '").append(this.searchBase).append("'");
		sb.append(", scope: ").append(
				(this.searchControls.getSearchScope() != SearchControls.SUBTREE_SCOPE) ? "single-level, " : "subtree");
		sb.append(", searchTimeLimit: ").append(this.searchControls.getTimeLimit());
		sb.append(", derefLinkFlag: ").append(this.searchControls.getDerefLinkFlag()).append(" ]");
		return sb.toString();
	}

}
