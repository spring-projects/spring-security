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

import javax.naming.ldap.LdapName;

import org.springframework.ldap.core.DistinguishedName;

/**
 * Constructs an Ldap Distinguished Name from a username.
 *
 * @author Luke Taylor
 */
public interface LdapUsernameToDnMapper {

	/**
	 * @deprecated Use {@link #buildLdapName(String)} instead
	 */
	@Deprecated
	DistinguishedName buildDn(String username);

	default LdapName buildLdapName(String username) {
		return org.springframework.ldap.support.LdapUtils.newLdapName(buildDn(username));
	}

}
