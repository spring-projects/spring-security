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

package org.springframework.security.ldap.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.ldap.core.AuthenticationSource;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.util.Assert;

/**
 * An AuthenticationSource to retrieve authentication information stored in Spring
 * Security's {@link SecurityContextHolder}.
 * <p>
 * This is a copy of Spring LDAP's AcegiAuthenticationSource, updated for use with Spring
 * Security 2.0.
 *
 * @author Mattias Arthursson
 * @author Luke Taylor
 * @since 2.0
 */
public class SpringSecurityAuthenticationSource implements AuthenticationSource {

	private static final Log log = LogFactory.getLog(SpringSecurityAuthenticationSource.class);

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	/**
	 * Get the principals of the logged in user, in this case the distinguished name.
	 * @return the distinguished name of the logged in user.
	 */
	@Override
	public String getPrincipal() {
		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (authentication == null) {
			log.debug("Returning empty String as Principal since authentication is null");
			return "";
		}
		Object principal = authentication.getPrincipal();
		if (principal instanceof LdapUserDetails) {
			LdapUserDetails details = (LdapUserDetails) principal;
			return details.getDn();
		}
		if (authentication instanceof AnonymousAuthenticationToken) {
			log.debug("Returning empty String as Principal since authentication is anonymous");
			return "";
		}
		throw new IllegalArgumentException(
				"The principal property of the authentication object" + "needs to be an LdapUserDetails.");
	}

	/**
	 * @see org.springframework.ldap.core.AuthenticationSource#getCredentials()
	 */
	@Override
	public String getCredentials() {
		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (authentication == null) {
			log.debug("Returning empty String as Credentials since authentication is null");
			return "";
		}
		return (String) authentication.getCredentials();
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

}
