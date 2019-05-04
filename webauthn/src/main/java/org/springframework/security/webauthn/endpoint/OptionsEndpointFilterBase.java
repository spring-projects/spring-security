/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn.endpoint;

import com.webauthn4j.converter.util.JsonConverter;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;

/**
 * A filter for providing WebAuthn option parameters to clients.
 *
 * @author Yoshikazu Nojima
 */
public abstract class OptionsEndpointFilterBase extends GenericFilterBean {


	//~ Instance fields
	// ================================================================================================

	/**
	 * Url this filter should get activated on.
	 */
	protected String filterProcessesUrl;
	protected JsonConverter jsonConverter;

	private AuthenticationTrustResolver trustResolver;
	private MFATokenEvaluator mfaTokenEvaluator;


	// ~ Constructors
	// ===================================================================================================

	public OptionsEndpointFilterBase(JsonConverter jsonConverter) {
		this.jsonConverter = jsonConverter;
		this.trustResolver = new AuthenticationTrustResolverImpl();
		this.mfaTokenEvaluator = new MFATokenEvaluatorImpl();
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public void afterPropertiesSet() {
		checkConfig();
	}

	protected void checkConfig() {
		Assert.notNull(filterProcessesUrl, "filterProcessesUrl must not be null");
		Assert.notNull(jsonConverter, "jsonConverter must not be null");
		Assert.notNull(trustResolver, "trustResolver must not be null");
		Assert.notNull(mfaTokenEvaluator, "mfaTokenEvaluator must not be null");
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		FilterInvocation fi = new FilterInvocation(request, response, chain);

		if (!processFilter(fi.getRequest())) {
			chain.doFilter(request, response);
			return;
		}

		try {
			Serializable options = processRequest(fi.getRequest());
			writeResponse(fi.getResponse(), options);
		} catch (RuntimeException e) {
			logger.debug(e);
			writeErrorResponse(fi.getResponse(), e);
		}

	}

	protected abstract Serializable processRequest(HttpServletRequest request);

	public AuthenticationTrustResolver getTrustResolver() {
		return trustResolver;
	}

	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		this.trustResolver = trustResolver;
	}

	public MFATokenEvaluator getMFATokenEvaluator() {
		return mfaTokenEvaluator;
	}

	public void setMFATokenEvaluator(MFATokenEvaluator mfaTokenEvaluator) {
		this.mfaTokenEvaluator = mfaTokenEvaluator;
	}


	/**
	 * The filter will be used in case the URL of the request contains the FILTER_URL.
	 *
	 * @param request request used to determine whether to enable this filter
	 * @return true if this filter should be used
	 */
	private boolean processFilter(HttpServletRequest request) {
		return (request.getRequestURI().contains(filterProcessesUrl));
	}

	void writeResponse(HttpServletResponse httpServletResponse, Serializable data) throws IOException {
		String responseText = jsonConverter.writeValueAsString(data);
		httpServletResponse.setContentType("application/json");
		httpServletResponse.getWriter().print(responseText);
	}

	void writeErrorResponse(HttpServletResponse httpServletResponse, RuntimeException e) throws IOException {
		ErrorResponse errorResponse;
		int statusCode;
		if (e instanceof InsufficientAuthenticationException) {
			errorResponse = new ErrorResponse("Anonymous access is prohibited");
			statusCode = HttpServletResponse.SC_FORBIDDEN;
		} else {
			errorResponse = new ErrorResponse("The server encountered an internal error");
			statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
		}
		String errorResponseText = jsonConverter.writeValueAsString(errorResponse);
		httpServletResponse.setContentType("application/json");
		httpServletResponse.getWriter().print(errorResponseText);
		httpServletResponse.setStatus(statusCode);
	}

	String getLoginUsername() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || (trustResolver.isAnonymous(authentication) && !mfaTokenEvaluator.isMultiFactorAuthentication(authentication))) {
			return null;
		} else {
			return authentication.getName();
		}
	}

	public void setFilterProcessesUrl(String filterProcessesUrl) {
		this.filterProcessesUrl = filterProcessesUrl;
	}
}
