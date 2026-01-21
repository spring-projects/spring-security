/*
 * Copyright 2004-present the original author or authors.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.util.StringUtils;

import javax.naming.InvalidNameException;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * An LDAP authority populator that can recursively search static nested groups.
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

	private ContextSource contextSource;

	/**
	 * Constructor for group search scenarios. <tt>userRoleAttributes</tt> may still be
	 * set as a property.
	 * @param contextSource supplies the contexts used to search for user roles.
	 * @param groupSearchBase if this is an empty string the search will be performed from
	 * the root DN of the
	 */
	public NestedLdapAuthoritiesPopulator(ContextSource contextSource, String groupSearchBase) {
		super(contextSource, groupSearchBase);
		this.contextSource = contextSource;
	}

	@Override
	public Set<GrantedAuthority> getGroupMembershipRoles(String userDn, String username) {
		if (getGroupSearchBase() == null) {
			return new HashSet<>();
		}
		Set<GrantedAuthority> authorities = new HashSet<>();
		try {
			performNestedSearch(new LdapName(userDn), username, authorities, getMaxSearchDepth());
		}
		catch (InvalidNameException e) {
			throw LdapUtils.convertLdapException(e);
		}
		return authorities;
	}

	/**
	 * Performs the nested group search
	 * @param userDn - the userDN to search for, will become the group DN for subsequent
	 * searches
	 * @param username - the username of the user
	 * @param authorities - the authorities set that will be populated, must not be null
	 * @param depth - the depth remaining, when 0 recursions will end
	 */
	private void performNestedSearch(Name userDn, String username, Set<GrantedAuthority> authorities, int depth) {
		if (depth == 0) {
			// back out of recursion
			logger.debug(LogMessage.of(() -> "Aborted search since max depth reached," + " for roles for user '"
					+ username + " with DN = " + userDn + " and filter " + getGroupSearchFilter() + " in search base '"
					+ getGroupSearchBase() + "'"));
			return;
		}
		logger.trace(LogMessage.of(() -> "Searching for roles for user " + username + " with DN " + userDn
				+ " and filter " + getGroupSearchFilter() + " in search base " + getGroupSearchBase()));
		if (getAttributeNames() == null) {
			setAttributeNames(new HashSet<>());
		}
		if (StringUtils.hasText(getGroupRoleAttribute())) {
			getAttributeNames().add(getGroupRoleAttribute());
		}
		LdapQuery query = LdapQueryBuilder.query()
			.base(getGroupSearchBase())
			// .attributes(getGroupRoleAttribute()) // TODO the original implementation
			// does not use it??
			.filter(getGroupSearchFilter(), userDn, username);

		AtomicBoolean circular = new AtomicBoolean(false);
		Set<String> roles = new HashSet<>();
		getLdapClient().search().query(query).toEntryStream().forEach(entry -> {
			logger.debug(LogMessage.of(() -> "Found roles from search " + entry));
			Attributes attributes = entry.getAttributes();

			Name dn = entry.getDn();
			String[] userRoles = entry.getStringAttributes(getGroupRoleAttribute());

			if (userRoles != null)
				roles.addAll(Arrays.asList(userRoles));

			for (String role : roles) {
				if (isConvertToUpperCase()) {
					role = role.toUpperCase(Locale.ROOT);
				}
				role = getRolePrefix() + role;
				// if the group already exist, we will not search for it's parents again.
				// this prevents a forever loop for a misconfigured ldap directory
				circular.set(circular.get() | (!authorities.add(new LdapAuthority(role, dn, attributes))));
			}
			String roleName = (!roles.isEmpty()) ? roles.iterator().next() : dn.toString();
			if (!circular.get()) {
				performNestedSearch(dn, roleName, authorities, (depth - 1));
			}
		});
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
