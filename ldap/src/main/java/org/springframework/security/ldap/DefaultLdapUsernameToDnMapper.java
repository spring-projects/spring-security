/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.ldap;

import org.springframework.ldap.core.DistinguishedName;

/**
 * This implementation appends a name component to the <tt>userDnBase</tt> context using
 * the <tt>usernameAttributeName</tt> property. So if the <tt>uid</tt> attribute is used
 * to store the username, and the base DN is <tt>cn=users</tt> and we are creating a new
 * user called "sam", then the DN will be <tt>uid=sam,cn=users</tt>.
 *
 * @author Luke Taylor
 */
public class DefaultLdapUsernameToDnMapper implements LdapUsernameToDnMapper {

	private final String userDnBase;

	private final String usernameAttribute;

	/**
	 * @param userDnBase the base name of the DN
	 * @param usernameAttribute the attribute to append for the username component.
	 */
	public DefaultLdapUsernameToDnMapper(String userDnBase, String usernameAttribute) {
		this.userDnBase = userDnBase;
		this.usernameAttribute = usernameAttribute;
	}

	/**
	 * Assembles the Distinguished Name that should be used the given username.
	 */
	@Override
	public DistinguishedName buildDn(String username) {
		DistinguishedName dn = new DistinguishedName(this.userDnBase);

		dn.add(this.usernameAttribute, username);

		return dn;
	}

}
