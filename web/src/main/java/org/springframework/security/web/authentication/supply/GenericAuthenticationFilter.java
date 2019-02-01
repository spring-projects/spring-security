/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.authentication.supply;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.AuthenticationType;
import org.springframework.security.web.authentication.www.AuthenticationTypeParser;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * @author Sergey Bespalov
 *
 */
public class GenericAuthenticationFilter extends AbstractAuthenticationProcessingFilter
		implements AuthenticationFailureHandler {

	public static final String ATTRIBUTE_NAME_AUTHENTICATION_TYPE = GenericAuthenticationFilter.class.getName()
			+ ".authenticationTypeName";

	private AuthenticationSupplierRegistry authenticationSupplierRegistry;
	private AuthenticationTypeParser authenticationTypeParser = new AuthenticationTypeParser();

	public GenericAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
		super(requiresAuthenticationRequestMatcher);
		setAuthenticationFailureHandler(this);
	}

	public GenericAuthenticationFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
		setAuthenticationFailureHandler(this);
	}

	public AuthenticationTypeParser getAuthenticationTypeParser() {
		return authenticationTypeParser;
	}

	public void setAuthenticationTypeParser(AuthenticationTypeParser authenticationTypeParser) {
		this.authenticationTypeParser = authenticationTypeParser;
	}

	public AuthenticationSupplierRegistry getAuthenticationSupplierRegistry() {
		return authenticationSupplierRegistry;
	}

	public void setAuthenticationSupplierRegistry(AuthenticationSupplierRegistry authenticationSupplierRegistry) {
		this.authenticationSupplierRegistry = authenticationSupplierRegistry;
	}

	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		Assert.notNull(authenticationSupplierRegistry, "authenticationSupplierRegistry must not be null");
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		if (!super.requiresAuthentication(request, response)) {
			return false;
		}

		AuthenticationType authenticationType = getAuthenticationTypeParser().parseAuthenticationType(request);
		if (authenticationType == null) {
			return false;
		}

		request.setAttribute(ATTRIBUTE_NAME_AUTHENTICATION_TYPE, authenticationType);

		AuthenticationSupplier<?> authenticationSupplier = getAuthenticationSupplierRegistry()
				.lookupSupplierByAuthenticationType(authenticationType);
		if (authenticationSupplier == null) {
			return false;
		}

		Authentication authentication;
		try {
			authentication = authenticationSupplier.supply(request);
		} catch (AuthenticationException e) {
			onAuthenticationFailure(request, response, e);

			return true;
		}
		SecurityContextHolder.getContext().setAuthentication(authentication);

		return true;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			return null;
		}

		if (authentication.isAuthenticated()) {
			return authentication;
		}

		return getAuthenticationManager().authenticate(authentication);
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		AuthenticationType authenticationType = (AuthenticationType) request.getAttribute(ATTRIBUTE_NAME_AUTHENTICATION_TYPE);

		AuthenticationSupplier<?> authenticationSupplier = getAuthenticationSupplierRegistry()
				.lookupSupplierByAuthenticationType(authenticationType);
		authenticationSupplier.commence(request, response, exception);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		super.successfulAuthentication(request, response, chain, authResult);

		chain.doFilter(request, response);
	}


}
