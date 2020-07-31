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

package org.springframework.security.access.vote;

import java.util.Collection;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Votes if any {@link ConfigAttribute#getAttribute()} starts with a prefix indicating
 * that it is a role. The default prefix string is <Code>ROLE_</code>, but this may be
 * overridden to any value. It may also be set to empty, which means that essentially any
 * attribute will be voted on. As described further below, the effect of an empty prefix
 * may not be quite desirable.
 * <p>
 * Abstains from voting if no configuration attribute commences with the role prefix.
 * Votes to grant access if there is an exact matching
 * {@link org.springframework.security.core.GrantedAuthority} to a
 * <code>ConfigAttribute</code> starting with the role prefix. Votes to deny access if
 * there is no exact matching <code>GrantedAuthority</code> to a
 * <code>ConfigAttribute</code> starting with the role prefix.
 * <p>
 * An empty role prefix means that the voter will vote for every ConfigAttribute. When
 * there are different categories of ConfigAttributes used, this will not be optimal since
 * the voter will be voting for attributes which do not represent roles. However, this
 * option may be of some use when using pre-existing role names without a prefix, and no
 * ability exists to prefix them with a role prefix on reading them in, such as provided
 * for example in {@link org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl}.
 * <p>
 * All comparisons and prefixes are case sensitive.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 */
public class RoleVoter implements AccessDecisionVoter<Object> {

	private String rolePrefix = "ROLE_";

	public String getRolePrefix() {
		return this.rolePrefix;
	}

	/**
	 * Allows the default role prefix of <code>ROLE_</code> to be overridden. May be set
	 * to an empty value, although this is usually not desirable.
	 * @param rolePrefix the new prefix
	 */
	public void setRolePrefix(String rolePrefix) {
		this.rolePrefix = rolePrefix;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		return (attribute.getAttribute() != null) && attribute.getAttribute().startsWith(getRolePrefix());
	}

	/**
	 * This implementation supports any type of class, because it does not query the
	 * presented secure object.
	 * @param clazz the secure object
	 * @return always <code>true</code>
	 */
	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}

	@Override
	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
		if (authentication == null) {
			return ACCESS_DENIED;
		}
		int result = ACCESS_ABSTAIN;
		Collection<? extends GrantedAuthority> authorities = extractAuthorities(authentication);
		for (ConfigAttribute attribute : attributes) {
			if (this.supports(attribute)) {
				result = ACCESS_DENIED;
				// Attempt to find a matching granted authority
				for (GrantedAuthority authority : authorities) {
					if (attribute.getAttribute().equals(authority.getAuthority())) {
						return ACCESS_GRANTED;
					}
				}
			}
		}
		return result;
	}

	Collection<? extends GrantedAuthority> extractAuthorities(Authentication authentication) {
		return authentication.getAuthorities();
	}

}
