/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.ldap;

import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

/**
 * Creates an {@link AuthenticationManager} that can perform LDAP authentication.
 *
 * @author Eleftheria Stein
 * @since 5.7
 */
public abstract class AbstractLdapAuthenticationManagerFactory<T extends AbstractLdapAuthenticator> {

	AbstractLdapAuthenticationManagerFactory(BaseLdapPathContextSource contextSource) {
		this.contextSource = contextSource;
	}

	private BaseLdapPathContextSource contextSource;

	private String[] userDnPatterns;

	private LdapAuthoritiesPopulator ldapAuthoritiesPopulator;

	private GrantedAuthoritiesMapper authoritiesMapper;

	private UserDetailsContextMapper userDetailsContextMapper;

	private String userSearchFilter;

	private String userSearchBase = "";

	/**
	 * Sets the {@link BaseLdapPathContextSource} used to perform LDAP authentication.
	 * @param contextSource the {@link BaseLdapPathContextSource} used to perform LDAP
	 * authentication
	 */
	public void setContextSource(BaseLdapPathContextSource contextSource) {
		this.contextSource = contextSource;
	}

	/**
	 * Gets the {@link BaseLdapPathContextSource} used to perform LDAP authentication.
	 * @return the {@link BaseLdapPathContextSource} used to perform LDAP authentication
	 */
	protected final BaseLdapPathContextSource getContextSource() {
		return this.contextSource;
	}

	/**
	 * Sets the {@link LdapAuthoritiesPopulator} used to obtain a list of granted
	 * authorities for an LDAP user.
	 * @param ldapAuthoritiesPopulator the {@link LdapAuthoritiesPopulator} to use
	 */
	public void setLdapAuthoritiesPopulator(LdapAuthoritiesPopulator ldapAuthoritiesPopulator) {
		this.ldapAuthoritiesPopulator = ldapAuthoritiesPopulator;
	}

	/**
	 * Sets the {@link GrantedAuthoritiesMapper} used for converting the authorities
	 * loaded from storage to a new set of authorities which will be associated to the
	 * {@link UsernamePasswordAuthenticationToken}.
	 * @param authoritiesMapper the {@link GrantedAuthoritiesMapper} used for mapping the
	 * user's authorities
	 */
	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	/**
	 * Sets a custom strategy to be used for creating the {@link UserDetails} which will
	 * be stored as the principal in the {@link Authentication}.
	 * @param userDetailsContextMapper the strategy instance
	 */
	public void setUserDetailsContextMapper(UserDetailsContextMapper userDetailsContextMapper) {
		this.userDetailsContextMapper = userDetailsContextMapper;
	}

	/**
	 * If your users are at a fixed location in the directory (i.e. you can work out the
	 * DN directly from the username without doing a directory search), you can use this
	 * attribute to map directly to the DN. It maps directly to the userDnPatterns
	 * property of AbstractLdapAuthenticator. The value is a specific pattern used to
	 * build the user's DN, for example "uid={0},ou=people". The key "{0}" must be present
	 * and will be substituted with the username.
	 * @param userDnPatterns the LDAP patterns for finding the usernames
	 */
	public void setUserDnPatterns(String... userDnPatterns) {
		this.userDnPatterns = userDnPatterns;
	}

	/**
	 * The LDAP filter used to search for users (optional). For example "(uid={0})". The
	 * substituted parameter is the user's login name.
	 * @param userSearchFilter the LDAP filter used to search for users
	 */
	public void setUserSearchFilter(String userSearchFilter) {
		this.userSearchFilter = userSearchFilter;
	}

	/**
	 * Search base for user searches. Defaults to "". Only used with
	 * {@link #setUserSearchFilter(String)}.
	 * @param userSearchBase search base for user searches
	 */
	public void setUserSearchBase(String userSearchBase) {
		this.userSearchBase = userSearchBase;
	}

	/**
	 * Returns the configured {@link AuthenticationManager} that can be used to perform
	 * LDAP authentication.
	 * @return the configured {@link AuthenticationManager}
	 */
	public final AuthenticationManager createAuthenticationManager() {
		LdapAuthenticationProvider ldapAuthenticationProvider = getProvider();
		return new ProviderManager(ldapAuthenticationProvider);
	}

	private LdapAuthenticationProvider getProvider() {
		AbstractLdapAuthenticator authenticator = getAuthenticator();
		LdapAuthenticationProvider provider;
		if (this.ldapAuthoritiesPopulator != null) {
			provider = new LdapAuthenticationProvider(authenticator, this.ldapAuthoritiesPopulator);
		}
		else {
			provider = new LdapAuthenticationProvider(authenticator);
		}
		if (this.authoritiesMapper != null) {
			provider.setAuthoritiesMapper(this.authoritiesMapper);
		}
		if (this.userDetailsContextMapper != null) {
			provider.setUserDetailsContextMapper(this.userDetailsContextMapper);
		}
		return provider;
	}

	private AbstractLdapAuthenticator getAuthenticator() {
		AbstractLdapAuthenticator authenticator = createDefaultLdapAuthenticator();
		if (this.userSearchFilter != null) {
			authenticator.setUserSearch(
					new FilterBasedLdapUserSearch(this.userSearchBase, this.userSearchFilter, this.contextSource));
		}
		if (this.userDnPatterns != null && this.userDnPatterns.length > 0) {
			authenticator.setUserDnPatterns(this.userDnPatterns);
		}
		authenticator.afterPropertiesSet();
		return authenticator;
	}

	/**
	 * Allows subclasses to supply the default {@link AbstractLdapAuthenticator}.
	 * @return the {@link AbstractLdapAuthenticator} that will be configured for LDAP
	 * authentication
	 */
	protected abstract T createDefaultLdapAuthenticator();

}
