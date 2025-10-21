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

package org.springframework.security.web.authentication.preauth.j2ee;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.Attributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.MappableAttributesRetriever;
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.util.Assert;

/**
 * Implementation of AuthenticationDetailsSource which converts the user's J2EE roles (as
 * obtained by calling {@link HttpServletRequest#isUserInRole(String)}) into
 * {@code GrantedAuthority}s and stores these in the authentication details object.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource implements
		AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails>,
		InitializingBean {

	protected final Log logger = LogFactory.getLog(getClass());

	/**
	 * The role attributes returned by the configured {@code MappableAttributesRetriever}
	 */
	@SuppressWarnings("NullAway.Init")
	protected Set<String> j2eeMappableRoles;

	protected Attributes2GrantedAuthoritiesMapper j2eeUserRoles2GrantedAuthoritiesMapper = new SimpleAttributes2GrantedAuthoritiesMapper();

	/**
	 * Check that all required properties have been set.
	 */
	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.j2eeMappableRoles, "No mappable roles available");
		Assert.notNull(this.j2eeUserRoles2GrantedAuthoritiesMapper, "Roles to granted authorities mapper not set");
	}

	/**
	 * Obtains the list of user roles based on the current user's JEE roles. The
	 * {@link jakarta.servlet.http.HttpServletRequest#isUserInRole(String)} method is
	 * called for each of the values in the {@code j2eeMappableRoles} set to determine if
	 * that role should be assigned to the user.
	 * @param request the request which should be used to extract the user's roles.
	 * @return The subset of {@code j2eeMappableRoles} which applies to the current user
	 * making the request.
	 */
	protected Collection<String> getUserRoles(HttpServletRequest request) {
		ArrayList<String> j2eeUserRolesList = new ArrayList<>();
		for (String role : this.j2eeMappableRoles) {
			if (request.isUserInRole(role)) {
				j2eeUserRolesList.add(role);
			}
		}
		return j2eeUserRolesList;
	}

	/**
	 * Builds the authentication details object.
	 *
	 * @see org.springframework.security.authentication.AuthenticationDetailsSource#buildDetails(Object)
	 */
	@Override
	public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails buildDetails(HttpServletRequest context) {
		Collection<String> j2eeUserRoles = getUserRoles(context);
		Collection<? extends GrantedAuthority> userGrantedAuthorities = this.j2eeUserRoles2GrantedAuthoritiesMapper
			.getGrantedAuthorities(j2eeUserRoles);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("J2EE roles [%s] mapped to Granted Authorities: [%s]", j2eeUserRoles,
					userGrantedAuthorities));
		}
		return new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(context, userGrantedAuthorities);
	}

	/**
	 * @param aJ2eeMappableRolesRetriever The MappableAttributesRetriever to use
	 */
	public void setMappableRolesRetriever(MappableAttributesRetriever aJ2eeMappableRolesRetriever) {
		this.j2eeMappableRoles = Collections.unmodifiableSet(aJ2eeMappableRolesRetriever.getMappableAttributes());
	}

	/**
	 * @param mapper The Attributes2GrantedAuthoritiesMapper to use
	 */
	public void setUserRoles2GrantedAuthoritiesMapper(Attributes2GrantedAuthoritiesMapper mapper) {
		this.j2eeUserRoles2GrantedAuthoritiesMapper = mapper;
	}

}
