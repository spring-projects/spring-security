/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.cas.web;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apereo.cas.client.util.CommonUtils;
import org.apereo.cas.client.util.WebUtils;

import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Triggers a CAS gateway authentication attempt.
 * <p>
 * This filter requires a web session to work.
 * <p>
 * This filter must be placed after the {@link CasAuthenticationFilter} if it is defined.
 * <p>
 * The default implementation is {@link CasCookieGatewayRequestMatcher}.
 *
 * @author Michael Remond
 * @author Jerome LELEU
 */
public class TriggerCasGatewayFilter extends GenericFilterBean {

	public static final String TRIGGER_CAS_GATEWAY_AUTHENTICATION = "triggerCasGatewayAuthentication";

	private final String loginUrl;

	private final ServiceProperties serviceProperties;

	private RequestMatcher requestMatcher;

	private RequestCache requestCache = new HttpSessionRequestCache();

	public TriggerCasGatewayFilter(String loginUrl, ServiceProperties serviceProperties) {
		this.loginUrl = loginUrl;
		this.serviceProperties = serviceProperties;
		this.requestMatcher = new CasCookieGatewayRequestMatcher(this.serviceProperties, null);
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (this.requestMatcher.matches(request)) {
			// Try a CAS gateway authentication
			this.requestCache.saveRequest(request, response);
			HttpSession session = request.getSession(false);
			if (session != null) {
				session.setAttribute(TRIGGER_CAS_GATEWAY_AUTHENTICATION, true);
			}
			String urlEncodedService = WebUtils.constructServiceUrl(null, response, this.serviceProperties.getService(),
					null, this.serviceProperties.getArtifactParameter(), true);
			String redirectUrl = CommonUtils.constructRedirectUrl(this.loginUrl,
					this.serviceProperties.getServiceParameter(), urlEncodedService,
					this.serviceProperties.isSendRenew(), true);
			new DefaultRedirectStrategy().sendRedirect(request, response, redirectUrl);
		}
		else {
			// Continue in the chain
			chain.doFilter(request, response);
		}

	}

	public String getLoginUrl() {
		return this.loginUrl;
	}

	public ServiceProperties getServiceProperties() {
		return this.serviceProperties;
	}

	public RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	public RequestCache getRequestCache() {
		return this.requestCache;
	}

	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	public final void setRequestCache(RequestCache requestCache) {
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.requestCache = requestCache;
	}

}
