/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.mapping.SimpleMappableAttributesRetriever;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.preauth.j2ee.J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;

/**
 * Adds support for J2EE pre authentication.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link J2eePreAuthenticatedProcessingFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * <ul>
 * <li>{@link AuthenticationEntryPoint} is populated with an
 * {@link Http403ForbiddenEntryPoint}</li>
 * <li>A {@link PreAuthenticatedAuthenticationProvider} is populated into
 * {@link HttpSecurity#authenticationProvider(org.springframework.security.authentication.AuthenticationProvider)}
 * </li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link AuthenticationManager}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class JeeConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<JeeConfigurer<H>, H> {

	private J2eePreAuthenticatedProcessingFilter j2eePreAuthenticatedProcessingFilter;

	private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService;

	private Set<String> mappableRoles = new HashSet<>();

	/**
	 * Creates a new instance
	 * @see HttpSecurity#jee()
	 */
	public JeeConfigurer() {
	}

	/**
	 * Specifies roles to use map from the {@link HttpServletRequest} to the
	 * {@link UserDetails}. If {@link HttpServletRequest#isUserInRole(String)} returns
	 * true, the role is added to the {@link UserDetails}. This method is the equivalent
	 * of invoking {@link #mappableAuthorities(Set)}. Multiple invocations of
	 * {@link #mappableAuthorities(String...)} will override previous invocations.
	 *
	 * <p>
	 * There are no default roles that are mapped.
	 * </p>
	 * @param mappableRoles the roles to attempt to map to the {@link UserDetails} (i.e.
	 * "ROLE_USER", "ROLE_ADMIN", etc).
	 * @return the {@link JeeConfigurer} for further customizations
	 * @see SimpleMappableAttributesRetriever
	 * @see #mappableRoles(String...)
	 */
	public JeeConfigurer<H> mappableAuthorities(String... mappableRoles) {
		this.mappableRoles.clear();
		for (String role : mappableRoles) {
			this.mappableRoles.add(role);
		}
		return this;
	}

	/**
	 * Specifies roles to use map from the {@link HttpServletRequest} to the
	 * {@link UserDetails} and automatically prefixes it with "ROLE_". If
	 * {@link HttpServletRequest#isUserInRole(String)} returns true, the role is added to
	 * the {@link UserDetails}. This method is the equivalent of invoking
	 * {@link #mappableAuthorities(Set)}. Multiple invocations of
	 * {@link #mappableRoles(String...)} will override previous invocations.
	 *
	 * <p>
	 * There are no default roles that are mapped.
	 * </p>
	 * @param mappableRoles the roles to attempt to map to the {@link UserDetails} (i.e.
	 * "USER", "ADMIN", etc).
	 * @return the {@link JeeConfigurer} for further customizations
	 * @see SimpleMappableAttributesRetriever
	 * @see #mappableAuthorities(String...)
	 */
	public JeeConfigurer<H> mappableRoles(String... mappableRoles) {
		this.mappableRoles.clear();
		for (String role : mappableRoles) {
			this.mappableRoles.add("ROLE_" + role);
		}
		return this;
	}

	/**
	 * Specifies roles to use map from the {@link HttpServletRequest} to the
	 * {@link UserDetails}. If {@link HttpServletRequest#isUserInRole(String)} returns
	 * true, the role is added to the {@link UserDetails}. This is the equivalent of
	 * {@link #mappableRoles(String...)}. Multiple invocations of
	 * {@link #mappableAuthorities(Set)} will override previous invocations.
	 *
	 * <p>
	 * There are no default roles that are mapped.
	 * </p>
	 * @param mappableRoles the roles to attempt to map to the {@link UserDetails}.
	 * @return the {@link JeeConfigurer} for further customizations
	 * @see SimpleMappableAttributesRetriever
	 */
	public JeeConfigurer<H> mappableAuthorities(Set<String> mappableRoles) {
		this.mappableRoles = mappableRoles;
		return this;
	}

	/**
	 * Specifies the {@link AuthenticationUserDetailsService} that is used with the
	 * {@link PreAuthenticatedAuthenticationProvider}. The default is a
	 * {@link PreAuthenticatedGrantedAuthoritiesUserDetailsService}.
	 * @param authenticatedUserDetailsService the {@link AuthenticationUserDetailsService}
	 * to use.
	 * @return the {@link JeeConfigurer} for further configuration
	 */
	public JeeConfigurer<H> authenticatedUserDetailsService(
			AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticatedUserDetailsService) {
		this.authenticationUserDetailsService = authenticatedUserDetailsService;
		return this;
	}

	/**
	 * Allows specifying the {@link J2eePreAuthenticatedProcessingFilter} to use. If
	 * {@link J2eePreAuthenticatedProcessingFilter} is provided, all of its attributes
	 * must also be configured manually (i.e. all attributes populated in the
	 * {@link JeeConfigurer} are not used).
	 * @param j2eePreAuthenticatedProcessingFilter the
	 * {@link J2eePreAuthenticatedProcessingFilter} to use.
	 * @return the {@link JeeConfigurer} for further configuration
	 */
	public JeeConfigurer<H> j2eePreAuthenticatedProcessingFilter(
			J2eePreAuthenticatedProcessingFilter j2eePreAuthenticatedProcessingFilter) {
		this.j2eePreAuthenticatedProcessingFilter = j2eePreAuthenticatedProcessingFilter;
		return this;
	}

	/**
	 * Populates a {@link PreAuthenticatedAuthenticationProvider} into
	 * {@link HttpSecurity#authenticationProvider(org.springframework.security.authentication.AuthenticationProvider)}
	 * and a {@link Http403ForbiddenEntryPoint} into
	 * {@link HttpSecurityBuilder#setSharedObject(Class, Object)}
	 *
	 * @see org.springframework.security.config.annotation.SecurityConfigurerAdapter#init(org.springframework.security.config.annotation.SecurityBuilder)
	 */
	@Override
	public void init(H http) {
		PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
		authenticationProvider.setPreAuthenticatedUserDetailsService(getUserDetailsService());
		authenticationProvider = postProcess(authenticationProvider);

		// @formatter:off
		http
			.authenticationProvider(authenticationProvider)
			.setSharedObject(AuthenticationEntryPoint.class, new Http403ForbiddenEntryPoint());
		// @formatter:on
	}

	@Override
	public void configure(H http) {
		J2eePreAuthenticatedProcessingFilter filter = getFilter(http.getSharedObject(AuthenticationManager.class));
		http.addFilter(filter);
	}

	/**
	 * Gets the {@link J2eePreAuthenticatedProcessingFilter} or creates a default instance
	 * using the properties provided.
	 * @param authenticationManager the {@link AuthenticationManager} to use.
	 * @return the {@link J2eePreAuthenticatedProcessingFilter} to use.
	 */
	private J2eePreAuthenticatedProcessingFilter getFilter(AuthenticationManager authenticationManager) {
		if (this.j2eePreAuthenticatedProcessingFilter == null) {
			this.j2eePreAuthenticatedProcessingFilter = new J2eePreAuthenticatedProcessingFilter();
			this.j2eePreAuthenticatedProcessingFilter.setAuthenticationManager(authenticationManager);
			this.j2eePreAuthenticatedProcessingFilter
					.setAuthenticationDetailsSource(createWebAuthenticationDetailsSource());
			this.j2eePreAuthenticatedProcessingFilter = postProcess(this.j2eePreAuthenticatedProcessingFilter);
		}

		return this.j2eePreAuthenticatedProcessingFilter;
	}

	/**
	 * Gets the {@link AuthenticationUserDetailsService} that was specified or defaults to
	 * {@link PreAuthenticatedGrantedAuthoritiesUserDetailsService}.
	 * @return the {@link AuthenticationUserDetailsService} to use
	 */
	private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> getUserDetailsService() {
		return (this.authenticationUserDetailsService != null) ? this.authenticationUserDetailsService
				: new PreAuthenticatedGrantedAuthoritiesUserDetailsService();
	}

	/**
	 * Creates the {@link J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource} to set
	 * on the {@link J2eePreAuthenticatedProcessingFilter}. It is populated with a
	 * {@link SimpleMappableAttributesRetriever}.
	 * @return the {@link J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource} to use.
	 */
	private J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource createWebAuthenticationDetailsSource() {
		J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource detailsSource = new J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource();
		SimpleMappableAttributesRetriever rolesRetriever = new SimpleMappableAttributesRetriever();
		rolesRetriever.setMappableAttributes(this.mappableRoles);
		detailsSource.setMappableRolesRetriever(rolesRetriever);

		detailsSource = postProcess(detailsSource);
		return detailsSource;
	}

}
