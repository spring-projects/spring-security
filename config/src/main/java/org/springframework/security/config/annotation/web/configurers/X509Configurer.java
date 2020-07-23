/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

import javax.servlet.http.HttpServletRequest;

/**
 * Adds X509 based pre authentication to an application. Since validating the certificate
 * happens when the client connects, the requesting and validation of the client
 * certificate should be performed by the container. Spring Security will then use the
 * certificate to look up the {@link Authentication} for the user.
 *
 * <h2>Security Filters</h2>
 * <p>
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link X509AuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 * <p>
 * The following shared objects are created
 *
 * <ul>
 * <li>
 * {@link AuthenticationEntryPoint} is populated with an
 * {@link Http403ForbiddenEntryPoint}</li>
 * <li>A {@link PreAuthenticatedAuthenticationProvider} is populated into
 * {@link HttpSecurity#authenticationProvider(org.springframework.security.authentication.AuthenticationProvider)}
 * </li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 * <p>
 * The following shared objects are used:
 *
 * <ul>
 * <li>A {@link UserDetailsService} shared object is used if no
 * {@link AuthenticationUserDetailsService} is specified</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class X509Configurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<X509Configurer<H>, H> {
	private X509AuthenticationFilter x509AuthenticationFilter;
	private X509PrincipalExtractor x509PrincipalExtractor;
	private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService;
	private AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> authenticationDetailsSource;

	/**
	 * Creates a new instance
	 *
	 * @see HttpSecurity#x509()
	 */
	public X509Configurer() {
	}

	/**
	 * Allows specifying the entire {@link X509AuthenticationFilter}. If this is
	 * specified, the properties on {@link X509Configurer} will not be populated on the
	 * {@link X509AuthenticationFilter}.
	 *
	 * @param x509AuthenticationFilter the {@link X509AuthenticationFilter} to use
	 * @return the {@link X509Configurer} for further customizations
	 */
	public X509Configurer<H> x509AuthenticationFilter(
			X509AuthenticationFilter x509AuthenticationFilter) {
		this.x509AuthenticationFilter = x509AuthenticationFilter;
		return this;
	}

	/**
	 * Specifies the {@link X509PrincipalExtractor}
	 *
	 * @param x509PrincipalExtractor the {@link X509PrincipalExtractor} to use
	 * @return the {@link X509Configurer} to use
	 */
	public X509Configurer<H> x509PrincipalExtractor(X509PrincipalExtractor x509PrincipalExtractor) {
		this.x509PrincipalExtractor = x509PrincipalExtractor;
		return this;
	}

	/**
	 * Specifies the {@link AuthenticationDetailsSource}
	 *
	 * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} to use
	 * @return the {@link X509Configurer} to use
	 */
	public X509Configurer<H> authenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
		return this;
	}

	/**
	 * Shortcut for invoking
	 * {@link #authenticationUserDetailsService(AuthenticationUserDetailsService)} with a
	 * {@link UserDetailsByNameServiceWrapper}.
	 *
	 * @param userDetailsService the {@link UserDetailsService} to use
	 * @return the {@link X509Configurer} for further customizations
	 */
	public X509Configurer<H> userDetailsService(UserDetailsService userDetailsService) {
		UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService = new UserDetailsByNameServiceWrapper<>();
		authenticationUserDetailsService.setUserDetailsService(userDetailsService);
		return authenticationUserDetailsService(authenticationUserDetailsService);
	}

	/**
	 * Specifies the {@link AuthenticationUserDetailsService} to use. If not specified,
	 * the shared {@link UserDetailsService} will be used to create a
	 * {@link UserDetailsByNameServiceWrapper}.
	 *
	 * @param authenticationUserDetailsService the {@link AuthenticationUserDetailsService} to use
	 * @return the {@link X509Configurer} for further customizations
	 */
	public X509Configurer<H> authenticationUserDetailsService(
			AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService) {
		this.authenticationUserDetailsService = authenticationUserDetailsService;
		return this;
	}

	/**
	 * Specifies the regex to extract the principal from the certificate. If not
	 * specified, the default expression from {@link SubjectDnX509PrincipalExtractor} is
	 * used.
	 *
	 * @param subjectPrincipalRegex the regex to extract the user principal from the
	 *                              certificate (i.e. "CN=(.*?)(?:,|$)").
	 * @return the {@link X509Configurer} for further customizations
	 */
	public X509Configurer<H> subjectPrincipalRegex(String subjectPrincipalRegex) {
		SubjectDnX509PrincipalExtractor principalExtractor = new SubjectDnX509PrincipalExtractor();
		principalExtractor.setSubjectDnRegex(subjectPrincipalRegex);
		this.x509PrincipalExtractor = principalExtractor;
		return this;
	}

	@Override
	public void init(H http) {
		PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
		authenticationProvider.setPreAuthenticatedUserDetailsService(getAuthenticationUserDetailsService(http));

		// @formatter:off
		http
			.authenticationProvider(authenticationProvider)
			.setSharedObject(AuthenticationEntryPoint.class, new Http403ForbiddenEntryPoint());
		// @formatter:on
	}

	@Override
	public void configure(H http) {
		X509AuthenticationFilter filter = getFilter(http
				.getSharedObject(AuthenticationManager.class));
		http.addFilter(filter);
	}

	private X509AuthenticationFilter getFilter(AuthenticationManager authenticationManager) {
		if (x509AuthenticationFilter == null) {
			x509AuthenticationFilter = new X509AuthenticationFilter();
			x509AuthenticationFilter.setAuthenticationManager(authenticationManager);
			if (x509PrincipalExtractor != null) {
				x509AuthenticationFilter.setPrincipalExtractor(x509PrincipalExtractor);
			}
			if (authenticationDetailsSource != null) {
				x509AuthenticationFilter
						.setAuthenticationDetailsSource(authenticationDetailsSource);
			}
			x509AuthenticationFilter = postProcess(x509AuthenticationFilter);
		}

		return x509AuthenticationFilter;
	}

	private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> getAuthenticationUserDetailsService(
			H http) {
		if (authenticationUserDetailsService == null) {
			userDetailsService(http.getSharedObject(UserDetailsService.class));
		}
		return authenticationUserDetailsService;
	}

}
