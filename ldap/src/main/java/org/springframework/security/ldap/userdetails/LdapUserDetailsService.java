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

package org.springframework.security.ldap.userdetails;

import java.util.Collection;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.util.Assert;

/**
 * LDAP implementation of UserDetailsService based around an {@link LdapUserSearch} and an
 * {@link LdapAuthoritiesPopulator}. The final <tt>UserDetails</tt> object returned from
 * <tt>loadUserByUsername</tt> is created by the configured
 * <tt>UserDetailsContextMapper</tt>.
 *
 * @author Luke Taylor
 */
public class LdapUserDetailsService implements UserDetailsService {

	private final LdapUserSearch userSearch;

	private final LdapAuthoritiesPopulator authoritiesPopulator;

	private UserDetailsContextMapper userDetailsMapper = new LdapUserDetailsMapper();

	public LdapUserDetailsService(LdapUserSearch userSearch) {
		this(userSearch, new NullLdapAuthoritiesPopulator());
	}

	public LdapUserDetailsService(LdapUserSearch userSearch, LdapAuthoritiesPopulator authoritiesPopulator) {
		Assert.notNull(userSearch, "userSearch must not be null");
		Assert.notNull(authoritiesPopulator, "authoritiesPopulator must not be null");
		this.userSearch = userSearch;
		this.authoritiesPopulator = authoritiesPopulator;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		DirContextOperations userData = this.userSearch.searchForUser(username);

		return this.userDetailsMapper.mapUserFromContext(userData, username,
				this.authoritiesPopulator.getGrantedAuthorities(userData, username));
	}

	public void setUserDetailsMapper(UserDetailsContextMapper userDetailsMapper) {
		Assert.notNull(userDetailsMapper, "userDetailsMapper must not be null");
		this.userDetailsMapper = userDetailsMapper;
	}

	private static final class NullLdapAuthoritiesPopulator implements LdapAuthoritiesPopulator {

		@Override
		public Collection<GrantedAuthority> getGrantedAuthorities(DirContextOperations userDetails, String username) {
			return AuthorityUtils.NO_AUTHORITIES;
		}

	}

}
