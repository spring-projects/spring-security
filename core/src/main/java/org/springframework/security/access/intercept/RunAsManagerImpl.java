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

package org.springframework.security.access.intercept;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

/**
 * Basic concrete implementation of a {@link RunAsManager}.
 * <p>
 * Is activated if any {@link ConfigAttribute#getAttribute()} is prefixed with
 * <Code>RUN_AS_</code>. If found, it generates a new {@link RunAsUserToken} containing
 * the same principal, credentials and granted authorities as the original
 * {@link Authentication} object, along with {@link SimpleGrantedAuthority}s for each
 * <code>RUN_AS_</code> indicated. The created <code>SimpleGrantedAuthority</code>s will
 * be prefixed with a special prefix indicating that it is a role (default prefix value is
 * <code>ROLE_</code>), and then the remainder of the <code>RUN_AS_</code> keyword. For
 * example, <code>RUN_AS_FOO</code> will result in the creation of a granted authority of
 * <code>ROLE_RUN_AS_FOO</code>.
 * <p>
 * The role prefix may be overridden from the default, to match that used elsewhere, for
 * example when using an existing role database with another prefix. An empty role prefix
 * may also be specified. Note however that there are potential issues with using an empty
 * role prefix since different categories of {@link ConfigAttribute} can not be properly
 * discerned based on the prefix, with possible consequences when performing voting and
 * other actions. However, this option may be of some use when using pre-existing role
 * names without a prefix, and no ability exists to prefix them with a role prefix on
 * reading them in, such as provided for example in
 * {@link org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl}.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 */
public class RunAsManagerImpl implements RunAsManager, InitializingBean {

	// ~ Instance fields
	// ================================================================================================

	private String key;

	private String rolePrefix = "ROLE_";

	// ~ Methods
	// ========================================================================================================

	public void afterPropertiesSet() {
		Assert.notNull(key,
				"A Key is required and should match that configured for the RunAsImplAuthenticationProvider");
	}

	public Authentication buildRunAs(Authentication authentication, Object object,
			Collection<ConfigAttribute> attributes) {
		List<GrantedAuthority> newAuthorities = new ArrayList<>();

		for (ConfigAttribute attribute : attributes) {
			if (this.supports(attribute)) {
				GrantedAuthority extraAuthority = new SimpleGrantedAuthority(
						getRolePrefix() + attribute.getAttribute());
				newAuthorities.add(extraAuthority);
			}
		}

		if (newAuthorities.size() == 0) {
			return null;
		}

		// Add existing authorities
		newAuthorities.addAll(authentication.getAuthorities());

		return new RunAsUserToken(this.key, authentication.getPrincipal(), authentication.getCredentials(),
				newAuthorities, authentication.getClass());
	}

	public String getKey() {
		return key;
	}

	public String getRolePrefix() {
		return rolePrefix;
	}

	public void setKey(String key) {
		this.key = key;
	}

	/**
	 * Allows the default role prefix of <code>ROLE_</code> to be overridden. May be set
	 * to an empty value, although this is usually not desirable.
	 * @param rolePrefix the new prefix
	 */
	public void setRolePrefix(String rolePrefix) {
		this.rolePrefix = rolePrefix;
	}

	public boolean supports(ConfigAttribute attribute) {
		return attribute.getAttribute() != null && attribute.getAttribute().startsWith("RUN_AS_");
	}

	/**
	 * This implementation supports any type of class, because it does not query the
	 * presented secure object.
	 * @param clazz the secure object
	 * @return always <code>true</code>
	 */
	public boolean supports(Class<?> clazz) {
		return true;
	}

}
