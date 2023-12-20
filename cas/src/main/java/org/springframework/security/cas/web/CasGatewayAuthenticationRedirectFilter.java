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
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Redirects the request to the CAS server appending {@code gateway=true} to the URL. Upon
 * redirection, the {@link ServiceProperties#isSendRenew()} is ignored and considered as
 * {@code false} to align with the specification says that the {@code sendRenew} parameter
 * is not compatible with the {@code gateway} parameter. See the <a href=
 * "https://apereo.github.io/cas/6.6.x/protocol/CAS-Protocol-V2-Specification.html#:~:text=This%20parameter%20is%20not%20compatible%20with%20the%20%E2%80%9Crenew%E2%80%9D%20parameter.%20Behavior%20is%20undefined%20if%20both%20are%20set.">CAS
 * Protocol Specification</a> for more details. To allow other filters to know if the
 * request is a gateway request, this filter creates a session and add an attribute with
 * name {@link #CAS_GATEWAY_AUTHENTICATION_ATTR} which can be checked by other filters if
 * needed. It is recommended that this filter is placed after
 * {@link CasAuthenticationFilter} if it is defined.
 *
 * @author Michael Remond
 * @author Jerome LELEU
 * @author Marcus da Coregio
 * @since 6.3
 */
public final class CasGatewayAuthenticationRedirectFilter extends GenericFilterBean {

	public static final String CAS_GATEWAY_AUTHENTICATION_ATTR = "CAS_GATEWAY_AUTHENTICATION";

	private final String casLoginUrl;

	private final ServiceProperties serviceProperties;

	private RequestMatcher requestMatcher;

	private RequestCache requestCache = new HttpSessionRequestCache();

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	/**
	 * Constructs a new instance of this class
	 * @param serviceProperties the {@link ServiceProperties}
	 */
	public CasGatewayAuthenticationRedirectFilter(String casLoginUrl, ServiceProperties serviceProperties) {
		Assert.hasText(casLoginUrl, "casLoginUrl cannot be null or empty");
		Assert.notNull(serviceProperties, "serviceProperties cannot be null");
		this.casLoginUrl = casLoginUrl;
		this.serviceProperties = serviceProperties;
		this.requestMatcher = new CasGatewayResolverRequestMatcher(this.serviceProperties);
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (!this.requestMatcher.matches(request)) {
			chain.doFilter(request, response);
			return;
		}

		this.requestCache.saveRequest(request, response);
		HttpSession session = request.getSession(true);
		session.setAttribute(CAS_GATEWAY_AUTHENTICATION_ATTR, true);
		String urlEncodedService = WebUtils.constructServiceUrl(request, response, this.serviceProperties.getService(),
				null, this.serviceProperties.getServiceParameter(), this.serviceProperties.getArtifactParameter(),
				true);
		String redirectUrl = CommonUtils.constructRedirectUrl(this.casLoginUrl,
				this.serviceProperties.getServiceParameter(), urlEncodedService, false, true);
		this.redirectStrategy.sendRedirect(request, response, redirectUrl);
	}

	/**
	 * Sets the {@link RequestMatcher} used to trigger this filter. Defaults to
	 * {@link CasGatewayResolverRequestMatcher}.
	 * @param requestMatcher the {@link RequestMatcher} to use
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	/**
	 * Sets the {@link RequestCache} used to store the current request to be replayed
	 * after redirect from the CAS server. Defaults to {@link HttpSessionRequestCache}.
	 * @param requestCache the {@link RequestCache} to use
	 */
	public void setRequestCache(RequestCache requestCache) {
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.requestCache = requestCache;
	}

}
