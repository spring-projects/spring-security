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

package org.springframework.security.ldap.authentication.ad;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.naming.ldap.LdapName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

/**
 * The default strategy for obtaining user role information from the active directory.
 * Creates the user authority list from the values of the {@code memberOf} attribute
 * obtained from the user's Active Directory entry.
 *
 * @author Luke Taylor
 * @author Roman Zabaluev
 * @since 6.3
 */
public final class DefaultActiveDirectoryAuthoritiesPopulator implements LdapAuthoritiesPopulator {

	private final Log logger = LogFactory.getLog(getClass());

	@Override
	public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData,
			String username) {
		String[] groups = userData.getStringAttributes("memberOf");
		if (groups == null) {
			this.logger.debug("No values for 'memberOf' attribute.");
			return AuthorityUtils.NO_AUTHORITIES;
		}
		if (this.logger.isDebugEnabled()) {
			this.logger.debug("'memberOf' attribute values: " + Arrays.asList(groups));
		}

		List<GrantedAuthority> authorities = new ArrayList<>(groups.length);

		for (String group : groups) {
			LdapName name = LdapNameBuilder.newInstance(group).build();
			String authority = name.getRdn(name.size() - 1).getValue().toString();
			authorities.add(new SimpleGrantedAuthority(authority));
		}

		return authorities;
	}

}
