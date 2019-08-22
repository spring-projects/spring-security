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
package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Base class containing the logic used by strategies which handle redirection to a URL
 * and are passed an {@code Authentication} object as part of the contract. See
 * {@link AuthenticationSuccessHandler} and
 * {@link org.springframework.security.web.authentication.logout.LogoutSuccessHandler
 * LogoutSuccessHandler}, for example.
 * <p>
 * Uses the following logic sequence to determine how it should handle the
 * forward/redirect
 * <ul>
 * <li>
 * If the {@code alwaysUseDefaultTargetUrl} property is set to true, the
 * {@code defaultTargetUrl} property will be used for the destination.</li>
 * <li>
 * If a parameter matching the value of {@code targetUrlParameter} has been set on the
 * request, the value will be used as the destination. If you are enabling this
 * functionality, then you should ensure that the parameter cannot be used by an attacker
 * to redirect the user to a malicious site (by clicking on a URL with the parameter
 * included, for example). Typically it would be used when the parameter is included in
 * the login form and submitted with the username and password.</li>
 * <li>
 * If the {@code useReferer} property is set, the "Referer" HTTP header value will be
 * used, if present.</li>
 * <li>
 * As a fallback option, the {@code defaultTargetUrl} value will be used.</li>
 * </ul>
 *
 * @author Luke Taylor
 * @since 3.0
 */
public abstract class AbstractAuthenticationTargetUrlRequestHandler {

	protected final Log logger = LogFactory.getLog(this.getClass());
	private String targetUrlParameter = null;
	private String defaultTargetUrl = "/";
	private boolean alwaysUseDefaultTargetUrl = false;
	private boolean useReferer = false;
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	protected AbstractAuthenticationTargetUrlRequestHandler() {
	}

	/**
	 * Invokes the configured {@code RedirectStrategy} with the URL returned by the
	 * {@code determineTargetUrl} method.
	 * <p>
	 * The redirect will not be performed if the response has already been committed.
	 */
	protected void handle(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		String targetUrl = determineTargetUrl(request, response, authentication);

		if (response.isCommitted()) {
			logger.debug("Response has already been committed. Unable to redirect to "
					+ targetUrl);
			return;
		}

		redirectStrategy.sendRedirect(request, response, targetUrl);
	}

	/**
	 * Builds the target URL according to the logic defined in the main class Javadoc
	 *
	 * @since 5.2
	 */
	protected String determineTargetUrl(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication) {
		return determineTargetUrl(request, response);
	}

	/**
	 * Builds the target URL according to the logic defined in the main class Javadoc.
	 */
	protected String determineTargetUrl(HttpServletRequest request,
			HttpServletResponse response) {
		if (isAlwaysUseDefaultTargetUrl()) {
			return defaultTargetUrl;
		}

		// Check for the parameter and use that if available
		String targetUrl = null;

		if (targetUrlParameter != null) {
			targetUrl = request.getParameter(targetUrlParameter);

			if (StringUtils.hasText(targetUrl)) {
				logger.debug("Found targetUrlParameter in request: " + targetUrl);

				return targetUrl;
			}
		}

		if (useReferer && !StringUtils.hasLength(targetUrl)) {
			targetUrl = request.getHeader("Referer");
			logger.debug("Using Referer header: " + targetUrl);
		}

		if (!StringUtils.hasText(targetUrl)) {
			targetUrl = defaultTargetUrl;
			logger.debug("Using default Url: " + targetUrl);
		}

		return targetUrl;
	}

	/**
	 * Supplies the default target Url that will be used if no saved request is found or
	 * the {@code alwaysUseDefaultTargetUrl} property is set to true. If not set, defaults
	 * to {@code /}.
	 *
	 * @return the defaultTargetUrl property
	 */
	protected final String getDefaultTargetUrl() {
		return defaultTargetUrl;
	}

	/**
	 * Supplies the default target Url that will be used if no saved request is found in
	 * the session, or the {@code alwaysUseDefaultTargetUrl} property is set to true. If
	 * not set, defaults to {@code /}. It will be treated as relative to the web-app's
	 * context path, and should include the leading <code>/</code>. Alternatively,
	 * inclusion of a scheme name (such as "http://" or "https://") as the prefix will
	 * denote a fully-qualified URL and this is also supported.
	 *
	 * @param defaultTargetUrl
	 */
	public void setDefaultTargetUrl(String defaultTargetUrl) {
		Assert.isTrue(UrlUtils.isValidRedirectUrl(defaultTargetUrl),
				"defaultTarget must start with '/' or with 'http(s)'");
		this.defaultTargetUrl = defaultTargetUrl;
	}

	/**
	 * If <code>true</code>, will always redirect to the value of {@code defaultTargetUrl}
	 * (defaults to <code>false</code>).
	 */
	public void setAlwaysUseDefaultTargetUrl(boolean alwaysUseDefaultTargetUrl) {
		this.alwaysUseDefaultTargetUrl = alwaysUseDefaultTargetUrl;
	}

	protected boolean isAlwaysUseDefaultTargetUrl() {
		return alwaysUseDefaultTargetUrl;
	}

	/**
	 * If this property is set, the current request will be checked for this a parameter
	 * with this name and the value used as the target URL if present.
	 *
	 * @param targetUrlParameter the name of the parameter containing the encoded target
	 * URL. Defaults to null.
	 */
	public void setTargetUrlParameter(String targetUrlParameter) {
		if (targetUrlParameter != null) {
			Assert.hasText(targetUrlParameter, "targetUrlParameter cannot be empty");
		}
		this.targetUrlParameter = targetUrlParameter;
	}

	protected String getTargetUrlParameter() {
		return targetUrlParameter;
	}

	/**
	 * Allows overriding of the behaviour when redirecting to a target URL.
	 */
	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}

	protected RedirectStrategy getRedirectStrategy() {
		return redirectStrategy;
	}

	/**
	 * If set to {@code true} the {@code Referer} header will be used (if available).
	 * Defaults to {@code false}.
	 */
	public void setUseReferer(boolean useReferer) {
		this.useReferer = useReferer;
	}

}
