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

package org.springframework.security.ldap.userdetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import javax.naming.directory.SearchControls;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * The default strategy for obtaining user role information from the directory.
 * <p>
 * It obtains roles by performing a search for "groups" the user is a member of.
 * <p>
 * A typical group search scenario would be where each group/role is specified using the
 * <tt>groupOfNames</tt> (or <tt>groupOfUniqueNames</tt>) LDAP objectClass and the user's
 * DN is listed in the <tt>member</tt> (or <tt>uniqueMember</tt>) attribute to indicate
 * that they should be assigned that role. The following LDIF sample has the groups stored
 * under the DN <tt>ou=groups,dc=springframework,dc=org</tt> and a group called
 * "developers" with "ben" and "luke" as members:
 *
 * <pre>
 * dn: ou=groups,dc=springframework,dc=org
 * objectClass: top
 * objectClass: organizationalUnit
 * ou: groups
 *
 * dn: cn=developers,ou=groups,dc=springframework,dc=org
 * objectClass: groupOfNames
 * objectClass: top
 * cn: developers
 * description: Spring Security Developers
 * member: uid=ben,ou=people,dc=springframework,dc=org
 * member: uid=luke,ou=people,dc=springframework,dc=org
 * ou: developer
 * </pre>
 * <p>
 * The group search is performed within a DN specified by the <tt>groupSearchBase</tt>
 * property, which should be relative to the root DN of its <tt>ContextSource</tt>. If the
 * search base is null, group searching is disabled. The filter used in the search is
 * defined by the <tt>groupSearchFilter</tt> property, with the filter argument {0} being
 * the full DN of the user. You can also optionally use the parameter {1}, which will be
 * substituted with the username. You can also specify which attribute defines the role
 * name by setting the <tt>groupRoleAttribute</tt> property (the default is "cn").
 * <p>
 * The configuration below shows how the group search might be performed with the above
 * schema.
 *
 * <pre>
 * &lt;bean id="ldapAuthoritiesPopulator"
 *       class="org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator"&gt;
 *   &lt;constructor-arg ref="contextSource"/&gt;
 *   &lt;constructor-arg value="ou=groups"/&gt;
 *   &lt;property name="groupRoleAttribute" value="ou"/&gt;
 * &lt;!-- the following properties are shown with their default values --&gt;
 *   &lt;property name="searchSubtree" value="false"/&gt;
 *   &lt;property name="rolePrefix" value="ROLE_"/&gt;
 *   &lt;property name="convertToUpperCase" value="true"/&gt;
 * &lt;/bean&gt;
 * </pre>
 *
 * A search for roles for user "uid=ben,ou=people,dc=springframework,dc=org" would return
 * the single granted authority "ROLE_DEVELOPER".
 * <p>
 * The single-level search is performed by default. Setting the <tt>searchSubTree</tt>
 * property to true will enable a search of the entire subtree under
 * <tt>groupSearchBase</tt>.
 *
 * @author Luke Taylor
 * @author Filip Hanik
 */
public class DefaultLdapAuthoritiesPopulator implements LdapAuthoritiesPopulator {

	private static final Log logger = LogFactory.getLog(DefaultLdapAuthoritiesPopulator.class);

	/**
	 * A default role which will be assigned to all authenticated users if set
	 */
	private GrantedAuthority defaultRole;

	/**
	 * Template that will be used for searching
	 */
	private final SpringSecurityLdapTemplate ldapTemplate;

	/**
	 * Controls used to determine whether group searches should be performed over the full
	 * sub-tree from the base DN. Modified by searchSubTree property
	 */
	private final SearchControls searchControls = new SearchControls();

	/**
	 * The ID of the attribute which contains the role name for a group
	 */
	private String groupRoleAttribute = "cn";

	/**
	 * The base DN from which the search for group membership should be performed
	 */
	private final String groupSearchBase;

	/**
	 * The pattern to be used for the user search. {0} is the user's DN
	 */
	private String groupSearchFilter = "(member={0})";

	/**
	 * The role prefix that will be prepended to each role name
	 */
	private String rolePrefix = "ROLE_";

	/**
	 * Should we convert the role name to uppercase
	 */
	private boolean convertToUpperCase = true;

	/**
	 * The mapping function to be used to populate authorities.
	 */
	private Function<Map<String, List<String>>, GrantedAuthority> authorityMapper;

	/**
	 * Constructor for group search scenarios. <tt>userRoleAttributes</tt> may still be
	 * set as a property.
	 * @param contextSource supplies the contexts used to search for user roles.
	 * @param groupSearchBase if this is an empty string the search will be performed from
	 * the root DN of the context factory. If null, no search will be performed.
	 */
	public DefaultLdapAuthoritiesPopulator(ContextSource contextSource, String groupSearchBase) {
		Assert.notNull(contextSource, "contextSource must not be null");
		this.ldapTemplate = new SpringSecurityLdapTemplate(contextSource);
		getLdapTemplate().setSearchControls(getSearchControls());
		this.groupSearchBase = groupSearchBase;
		if (groupSearchBase == null) {
			logger.info("Will not perform group search since groupSearchBase is null.");
		}
		else if (groupSearchBase.isEmpty()) {
			logger.info("Will perform group search from the context source base since groupSearchBase is empty.");
		}
		this.authorityMapper = (record) -> {
			List<String> roles = record.get(this.groupRoleAttribute);
			if (CollectionUtils.isEmpty(roles)) {
				return null;
			}
			String role = roles.get(0);
			if (role == null) {
				return null;
			}
			if (this.convertToUpperCase) {
				role = role.toUpperCase(Locale.ROOT);
			}
			return new SimpleGrantedAuthority(this.rolePrefix + role);
		};
	}

	/**
	 * This method should be overridden if required to obtain any additional roles for the
	 * given user (on top of those obtained from the standard search implemented by this
	 * class).
	 * @param user the context representing the user who's roles are required
	 * @return the extra roles which will be merged with those returned by the group
	 * search
	 */

	protected Set<GrantedAuthority> getAdditionalRoles(DirContextOperations user, String username) {
		return null;
	}

	/**
	 * Obtains the authorities for the user who's directory entry is represented by the
	 * supplied LdapUserDetails object.
	 * @param user the user who's authorities are required
	 * @return the set of roles granted to the user.
	 */
	@Override
	public final Collection<GrantedAuthority> getGrantedAuthorities(DirContextOperations user, String username) {
		String userDn = user.getNameInNamespace();
		Set<GrantedAuthority> roles = getGroupMembershipRoles(userDn, username);
		Set<GrantedAuthority> extraRoles = getAdditionalRoles(user, username);
		if (extraRoles != null) {
			roles.addAll(extraRoles);
		}
		if (this.defaultRole != null) {
			roles.add(this.defaultRole);
		}
		List<GrantedAuthority> result = new ArrayList<>(roles.size());
		result.addAll(roles);
		logger.debug(LogMessage.format("Retrieved authorities for user %s", userDn));
		return result;
	}

	public Set<GrantedAuthority> getGroupMembershipRoles(String userDn, String username) {
		if (getGroupSearchBase() == null) {
			return new HashSet<>();
		}
		Set<GrantedAuthority> authorities = new HashSet<>();
		logger.trace(LogMessage.of(() -> "Searching for roles for user " + username + " with DN " + userDn
				+ " and filter " + this.groupSearchFilter + " in search base " + getGroupSearchBase()));
		Set<Map<String, List<String>>> userRoles = getLdapTemplate().searchForMultipleAttributeValues(
				getGroupSearchBase(), this.groupSearchFilter, new String[] { userDn, username },
				new String[] { this.groupRoleAttribute });
		logger.debug(LogMessage.of(() -> "Found roles from search " + userRoles));
		for (Map<String, List<String>> role : userRoles) {
			GrantedAuthority authority = this.authorityMapper.apply(role);
			if (authority != null) {
				authorities.add(authority);
			}
		}
		return authorities;
	}

	protected ContextSource getContextSource() {
		return getLdapTemplate().getContextSource();
	}

	protected String getGroupSearchBase() {
		return this.groupSearchBase;
	}

	/**
	 * Convert the role to uppercase
	 */
	public void setConvertToUpperCase(boolean convertToUpperCase) {
		this.convertToUpperCase = convertToUpperCase;
	}

	/**
	 * The default role which will be assigned to all users.
	 * @param defaultRole the role name, including any desired prefix.
	 */
	public void setDefaultRole(String defaultRole) {
		Assert.notNull(defaultRole, "The defaultRole property cannot be set to null");
		this.defaultRole = new SimpleGrantedAuthority(defaultRole);
	}

	public void setGroupRoleAttribute(String groupRoleAttribute) {
		Assert.notNull(groupRoleAttribute, "groupRoleAttribute must not be null");
		this.groupRoleAttribute = groupRoleAttribute;
	}

	public void setGroupSearchFilter(String groupSearchFilter) {
		Assert.notNull(groupSearchFilter, "groupSearchFilter must not be null");
		this.groupSearchFilter = groupSearchFilter;
	}

	/**
	 * Sets the prefix which will be prepended to the values loaded from the directory.
	 * Defaults to "ROLE_" for compatibility with <tt>RoleVoter</tt>.
	 */
	public void setRolePrefix(String rolePrefix) {
		Assert.notNull(rolePrefix, "rolePrefix must not be null");
		this.rolePrefix = rolePrefix;
	}

	/**
	 * If set to true, a subtree scope search will be performed. If false a single-level
	 * search is used.
	 * @param searchSubtree set to true to enable searching of the entire tree below the
	 * <tt>groupSearchBase</tt>.
	 */
	public void setSearchSubtree(boolean searchSubtree) {
		int searchScope = searchSubtree ? SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE;
		this.searchControls.setSearchScope(searchScope);
	}

	/**
	 * Sets the corresponding property on the underlying template, avoiding specific
	 * issues with Active Directory.
	 *
	 * @see LdapTemplate#setIgnoreNameNotFoundException(boolean)
	 */
	public void setIgnorePartialResultException(boolean ignore) {
		getLdapTemplate().setIgnorePartialResultException(ignore);
	}

	/**
	 * Sets the mapping function which will be used to create instances of
	 * {@link GrantedAuthority} given the context record.
	 * @param authorityMapper the mapping function
	 */
	public void setAuthorityMapper(Function<Map<String, List<String>>, GrantedAuthority> authorityMapper) {
		Assert.notNull(authorityMapper, "authorityMapper must not be null");
		this.authorityMapper = authorityMapper;
	}

	/**
	 * Returns the current LDAP template. Method available so that classes extending this
	 * can override the template used
	 * @return the LDAP template
	 * @see org.springframework.security.ldap.SpringSecurityLdapTemplate
	 */
	protected SpringSecurityLdapTemplate getLdapTemplate() {
		return this.ldapTemplate;
	}

	/**
	 * Returns the attribute name of the LDAP attribute that will be mapped to the role
	 * name Method available so that classes extending this can override
	 * @return the attribute name used for role mapping
	 * @see #setGroupRoleAttribute(String)
	 */
	protected final String getGroupRoleAttribute() {
		return this.groupRoleAttribute;
	}

	/**
	 * Returns the search filter configured for this populator Method available so that
	 * classes extending this can override
	 * @return the search filter
	 * @see #setGroupSearchFilter(String)
	 */
	protected final String getGroupSearchFilter() {
		return this.groupSearchFilter;
	}

	/**
	 * Returns the role prefix used by this populator Method available so that classes
	 * extending this can override
	 * @return the role prefix
	 * @see #setRolePrefix(String)
	 */
	protected final String getRolePrefix() {
		return this.rolePrefix;
	}

	/**
	 * Returns true if role names are converted to uppercase Method available so that
	 * classes extending this can override
	 * @return true if role names are converted to uppercase.
	 * @see #setConvertToUpperCase(boolean)
	 */
	protected final boolean isConvertToUpperCase() {
		return this.convertToUpperCase;
	}

	/**
	 * Returns the search controls Method available so that classes extending this can
	 * override the search controls used
	 * @return the search controls
	 */
	private SearchControls getSearchControls() {
		return this.searchControls;
	}

}
