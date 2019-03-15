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

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.dao.IncorrectResultSizeDataAccessException;

import org.springframework.util.Assert;

import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;

import javax.naming.directory.SearchControls;

/**
 * LdapUserSearch implementation which uses an Ldap filter to locate the user.
 *
 * @author Robert Sanders
 * @author Luke Taylor
 *
 * @see SearchControls
 */
public class FilterBasedLdapUserSearch implements LdapUserSearch {
	// ~ Static fields/initializers
	// =====================================================================================

	private static final Log logger = LogFactory.getLog(FilterBasedLdapUserSearch.class);

	// ~ Instance fields
	// ================================================================================================

	private final ContextSource contextSource;

	/**
	 * The LDAP SearchControls object used for the search. Shared between searches so
	 * shouldn't be modified once the bean has been configured.
	 */
	private final SearchControls searchControls = new SearchControls();

	/** Context name to search in, relative to the base of the configured ContextSource. */
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

	// ~ Constructors
	// ===================================================================================================

	public FilterBasedLdapUserSearch(String searchBase, String searchFilter,
			BaseLdapPathContextSource contextSource) {
		Assert.notNull(contextSource, "contextSource must not be null");
		Assert.notNull(searchFilter, "searchFilter must not be null.");
		Assert.notNull(searchBase,
				"searchBase must not be null (an empty string is acceptable).");

		this.searchFilter = searchFilter;
		this.contextSource = contextSource;
		this.searchBase = searchBase;

		setSearchSubtree(true);

		if (searchBase.length() == 0) {
			logger.info("SearchBase not set. Searches will be performed from the root: "
					+ contextSource.getBaseLdapPath());
		}
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * Return the LdapUserDetails containing the user's information
	 *
	 * @param username the username to search for.
	 *
	 * @return An LdapUserDetails object containing the details of the located user's
	 * directory entry
	 *
	 * @throws UsernameNotFoundException if no matching entry is found.
	 */
	public DirContextOperations searchForUser(String username) {
		if (logger.isDebugEnabled()) {
			logger.debug("Searching for user '" + username + "', with user search "
					+ this);
		}

		SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(
				contextSource);

		template.setSearchControls(searchControls);

		try {

			return template.searchForSingleEntry(searchBase, searchFilter,
					new String[] { username });

		}
		catch (IncorrectResultSizeDataAccessException notFound) {
			if (notFound.getActualSize() == 0) {
				throw new UsernameNotFoundException("User " + username
						+ " not found in directory.");
			}
			// Search should never return multiple results if properly configured, so just
			// rethrow
			throw notFound;
		}
	}

	/**
	 * Sets the corresponding property on the {@link SearchControls} instance used in the
	 * search.
	 *
	 * @param deref the derefLinkFlag value as defined in SearchControls..
	 */
	public void setDerefLinkFlag(boolean deref) {
		searchControls.setDerefLinkFlag(deref);
	}

	/**
	 * If true then searches the entire subtree as identified by context, if false (the
	 * default) then only searches the level identified by the context.
	 *
	 * @param searchSubtree true the underlying search controls should be set to
	 * SearchControls.SUBTREE_SCOPE rather than SearchControls.ONELEVEL_SCOPE.
	 */
	public void setSearchSubtree(boolean searchSubtree) {
		searchControls.setSearchScope(searchSubtree ? SearchControls.SUBTREE_SCOPE
				: SearchControls.ONELEVEL_SCOPE);
	}

	/**
	 * The time to wait before the search fails; the default is zero, meaning forever.
	 *
	 * @param searchTimeLimit the time limit for the search (in milliseconds).
	 */
	public void setSearchTimeLimit(int searchTimeLimit) {
		searchControls.setTimeLimit(searchTimeLimit);
	}

	/**
	 * Specifies the attributes that will be returned as part of the search.
	 * <p>
	 * null indicates that all attributes will be returned. An empty array indicates no
	 * attributes are returned.
	 *
	 * @param attrs An array of attribute names identifying the attributes that will be
	 * returned. Can be null.
	 */
	public void setReturningAttributes(String[] attrs) {
		searchControls.setReturningAttributes(attrs);
	}

	public String toString() {
		StringBuilder sb = new StringBuilder();

		sb.append("[ searchFilter: '").append(searchFilter).append("', ");
		sb.append("searchBase: '").append(searchBase).append("'");
		sb.append(", scope: ")
				.append(searchControls.getSearchScope() == SearchControls.SUBTREE_SCOPE ? "subtree"
						: "single-level, ");
		sb.append(", searchTimeLimit: ").append(searchControls.getTimeLimit());
		sb.append(", derefLinkFlag: ").append(searchControls.getDerefLinkFlag())
				.append(" ]");
		return sb.toString();
	}
}
