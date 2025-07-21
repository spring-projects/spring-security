/*
 * Copyright 2002-2024 the original author or authors.
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

import java.io.Serial;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * An authority that contains at least a DN and a role name for an LDAP entry but can also
 * contain other desired attributes to be fetched during an LDAP authority search.
 *
 * @author Filip Hanik
 */
public class LdapAuthority implements GrantedAuthority {

	@Serial
	private static final long serialVersionUID = 343193700821611354L;

	private final String dn;

	private final String role;

	private final Map<String, List<String>> attributes;

	/**
	 * Constructs an LdapAuthority that has a role and a DN but no other attributes
	 * @param role the principal's role
	 * @param dn the distinguished name
	 */
	public LdapAuthority(String role, String dn) {
		this(role, dn, null);
	}

	/**
	 * Constructs an LdapAuthority with the given role, DN and other LDAP attributes
	 * @param role the principal's role
	 * @param dn the distinguished name
	 * @param attributes additional LDAP attributes
	 */
	public LdapAuthority(String role, String dn, Map<String, List<String>> attributes) {
		Assert.notNull(role, "role can not be null");
		Assert.notNull(dn, "dn can not be null");
		this.role = role;
		this.dn = dn;
		this.attributes = attributes;
	}

	/**
	 * Returns the LDAP attributes
	 * @return the LDAP attributes, map can be null
	 */
	public Map<String, List<String>> getAttributes() {
		return this.attributes;
	}

	/**
	 * Returns the DN for this LDAP authority
	 * @return the distinguished name
	 */
	public String getDn() {
		return this.dn;
	}

	/**
	 * Returns the values for a specific attribute
	 * @param name the attribute name
	 * @return a String array, never null but may be zero length
	 */
	public List<String> getAttributeValues(String name) {
		List<String> result = null;
		if (this.attributes != null) {
			result = this.attributes.get(name);
		}
		return (result != null) ? result : Collections.emptyList();
	}

	/**
	 * Returns the first attribute value for a specified attribute
	 * @param name the attribute name
	 * @return the first attribute value for a specified attribute, may be null
	 */
	public String getFirstAttributeValue(String name) {
		List<String> result = getAttributeValues(name);
		return (!result.isEmpty()) ? result.get(0) : null;
	}

	@Override
	public String getAuthority() {
		return this.role;
	}

	/**
	 * Compares the LdapAuthority based on {@link #getAuthority()} and {@link #getDn()}
	 * values.
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof LdapAuthority other)) {
			return false;
		}
		if (!this.dn.equals(other.getDn())) {
			return false;
		}
		return this.role.equals(other.getAuthority());
	}

	@Override
	public int hashCode() {
		int result = this.dn.hashCode();
		result = 31 * result + ((this.role != null) ? this.role.hashCode() : 0);
		return result;
	}

	@Override
	public String toString() {
		return "LdapAuthority{" + "dn='" + this.dn + '\'' + ", role='" + this.role + '\'' + '}';
	}

}
