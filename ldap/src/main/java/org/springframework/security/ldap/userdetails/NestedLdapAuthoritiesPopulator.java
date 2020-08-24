/*
 * Copyright 2002-2014 the original author or authors.
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

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.ldap.core.ContextSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.util.StringUtils;

/**
 * A LDAP authority populator that can recursively search static nested groups.
 * <p>
 * An example of nested groups can be
 *
 * <pre>
 *  #Nested groups data
 *
 *  dn: uid=javadude,ou=people,dc=springframework,dc=org
 *  objectclass: top
 *  objectclass: person
 *  objectclass: organizationalPerson
 *  objectclass: inetOrgPerson
 *  cn: Java Dude
 *  sn: Dude
 *  uid: javadude
 *  userPassword: javadudespassword
 *
 *  dn: uid=groovydude,ou=people,dc=springframework,dc=org
 *  objectclass: top
 *  objectclass: person
 *  objectclass: organizationalPerson
 *  objectclass: inetOrgPerson
 *  cn: Groovy Dude
 *  sn: Dude
 *  uid: groovydude
 *  userPassword: groovydudespassword
 *
 *  dn: uid=closuredude,ou=people,dc=springframework,dc=org
 *  objectclass: top
 *  objectclass: person
 *  objectclass: organizationalPerson
 *  objectclass: inetOrgPerson
 *  cn: Closure Dude
 *  sn: Dude
 *  uid: closuredude
 *  userPassword: closuredudespassword
 *
 *  dn: uid=scaladude,ou=people,dc=springframework,dc=org
 *  objectclass: top
 *  objectclass: person
 *  objectclass: organizationalPerson
 *  objectclass: inetOrgPerson
 *  cn: Scala Dude
 *  sn: Dude
 *  uid: scaladude
 *  userPassword: scaladudespassword
 *
 *  dn: cn=j-developers,ou=jdeveloper,dc=springframework,dc=org
 *  objectclass: top
 *  objectclass: groupOfNames
 *  cn: j-developers
 *  ou: jdeveloper
 *  member: cn=java-developers,ou=groups,dc=springframework,dc=org
 *
 *  dn: cn=java-developers,ou=jdeveloper,dc=springframework,dc=org
 *  objectclass: top
 *  objectclass: groupOfNames
 *  cn: java-developers
 *  ou: jdeveloper
 *  member: cn=groovy-developers,ou=groups,dc=springframework,dc=org
 *  member: cn=scala-developers,ou=groups,dc=springframework,dc=org
 *  member: uid=javadude,ou=people,dc=springframework,dc=org
 *
 *  dn: cn=groovy-developers,ou=jdeveloper,dc=springframework,dc=org
 *  objectclass: top
 *  objectclass: groupOfNames
 *  cn: java-developers
 *  ou: jdeveloper
 *  member: cn=closure-developers,ou=groups,dc=springframework,dc=org
 *  member: uid=groovydude,ou=people,dc=springframework,dc=org
 *
 *  dn: cn=closure-developers,ou=jdeveloper,dc=springframework,dc=org
 *  objectclass: top
 *  objectclass: groupOfNames
 *  cn: java-developers
 *  ou: jdeveloper
 *  member: uid=closuredude,ou=people,dc=springframework,dc=org
 *
 *  dn: cn=scala-developers,ou=jdeveloper,dc=springframework,dc=org
 *  objectclass: top
 *  objectclass: groupOfNames
 *  cn: java-developers
 *  ou: jdeveloper
 *  member: uid=scaladude,ou=people,dc=springframework,dc=org *
 * </pre>
 *
 * @author Filip Hanik
 */

public class NestedLdapAuthoritiesPopulator extends DefaultLdapAuthoritiesPopulator {

	private static final Log logger = LogFactory.getLog(NestedLdapAuthoritiesPopulator.class);

	/**
	 * The attribute names to retrieve for each LDAP group
	 */
	private Set<String> attributeNames;

	/**
	 * Maximum search depth - represents the number of recursive searches performed
	 */
	private int maxSearchDepth = 10;

	/**
	 * Constructor for group search scenarios. <tt>userRoleAttributes</tt> may still be
	 * set as a property.
	 * @param contextSource supplies the contexts used to search for user roles.
	 * @param groupSearchBase if this is an empty string the search will be performed from
	 * the root DN of the
	 */
	public NestedLdapAuthoritiesPopulator(ContextSource contextSource, String groupSearchBase) {
		super(contextSource, groupSearchBase);
	}

	@Override
	public Set<GrantedAuthority> getGroupMembershipRoles(String userDn, String username) {
		if (getGroupSearchBase() == null) {
			return new HashSet<>();
		}
		Set<GrantedAuthority> authorities = new HashSet<>();
		performNestedSearch(userDn, username, authorities, getMaxSearchDepth());
		return authorities;
	}

	/**
	 * Performs the nested group search
	 * @param userDn - the userDN to search for, will become the group DN for subsequent
	 * searches
	 * @param username - the username of the user
	 * @param authorities - the authorities set that will be populated, must not be null
	 * @param depth - the depth remaining, when 0 recursion will end
	 */
	private void performNestedSearch(String userDn, String username, Set<GrantedAuthority> authorities, int depth) {
		if (depth == 0) {
			// back out of recursion
			logger.debug(LogMessage.of(() -> "Search aborted, max depth reached," + " for roles for user '" + username
					+ "', DN = " + "'" + userDn + "', with filter " + getGroupSearchFilter() + " in search base '"
					+ getGroupSearchBase() + "'"));
			return;
		}
		logger.debug(LogMessage.of(() -> "Searching for roles for user '" + username + "', DN = " + "'" + userDn
				+ "', with filter " + getGroupSearchFilter() + " in search base '" + getGroupSearchBase() + "'"));
		if (getAttributeNames() == null) {
			setAttributeNames(new HashSet<>());
		}
		if (StringUtils.hasText(getGroupRoleAttribute()) && !getAttributeNames().contains(getGroupRoleAttribute())) {
			getAttributeNames().add(getGroupRoleAttribute());
		}
		Set<Map<String, List<String>>> userRoles = getLdapTemplate().searchForMultipleAttributeValues(
				getGroupSearchBase(), getGroupSearchFilter(), new String[] { userDn, username },
				getAttributeNames().toArray(new String[0]));
		logger.debug(LogMessage.format("Roles from search: %s", userRoles));
		for (Map<String, List<String>> record : userRoles) {
			boolean circular = false;
			String dn = record.get(SpringSecurityLdapTemplate.DN_KEY).get(0);
			List<String> roleValues = record.get(getGroupRoleAttribute());
			Set<String> roles = new HashSet<>();
			if (roleValues != null) {
				roles.addAll(roleValues);
			}
			for (String role : roles) {
				if (isConvertToUpperCase()) {
					role = role.toUpperCase();
				}
				role = getRolePrefix() + role;
				// if the group already exist, we will not search for it's parents again.
				// this prevents a forever loop for a misconfigured ldap directory
				circular = circular | (!authorities.add(new LdapAuthority(role, dn, record)));
			}
			String roleName = (roles.size() > 0) ? roles.iterator().next() : dn;
			if (!circular) {
				performNestedSearch(dn, roleName, authorities, (depth - 1));
			}
		}
	}

	/**
	 * Returns the attribute names that this populator has been configured to retrieve
	 * Value can be null, represents fetch all attributes
	 * @return the attribute names or null for all
	 */
	private Set<String> getAttributeNames() {
		return this.attributeNames;
	}

	/**
	 * Sets the attribute names to retrieve for each ldap groups. Null means retrieve all
	 * @param attributeNames - the names of the LDAP attributes to retrieve
	 */
	public void setAttributeNames(Set<String> attributeNames) {
		this.attributeNames = attributeNames;
	}

	/**
	 * How far should a nested search go. Depth is calculated in the number of levels we
	 * search up for parent groups.
	 * @return the max search depth, default is 10
	 */
	private int getMaxSearchDepth() {
		return this.maxSearchDepth;
	}

	/**
	 * How far should a nested search go. Depth is calculated in the number of levels we
	 * search up for parent groups.
	 * @param maxSearchDepth the max search depth
	 */
	public void setMaxSearchDepth(int maxSearchDepth) {
		this.maxSearchDepth = maxSearchDepth;
	}

}
