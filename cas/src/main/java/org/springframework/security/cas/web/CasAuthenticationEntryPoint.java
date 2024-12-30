/*
 * Copyright 2002-2024 the original author or authors.
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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apereo.cas.client.util.CommonUtils;
import org.apereo.cas.client.util.WebUtils;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.Assert;

/**
 * Used by the <code>ExceptionTranslationFilter</code> to commence authentication via the
 * JA-SIG Central Authentication Service (CAS).
 * <p>
 * The user's browser will be redirected to the JA-SIG CAS enterprise-wide login page.
 * This page is specified by the <code>loginUrl</code> property. Once login is complete,
 * the CAS login page will redirect to the page indicated by the <code>service</code>
 * property. The <code>service</code> is a HTTP URL belonging to the current application.
 * The <code>service</code> URL is monitored by the {@link CasAuthenticationFilter}, which
 * will validate the CAS login was successful.
 *
 * @author Ben Alex
 * @author Scott Battaglia
 */
public class CasAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {

	private ServiceProperties serviceProperties;

	private String loginUrl;

	/**
	 * Determines whether the Service URL should include the session id for the specific
	 * user. As of CAS 3.0.5, the session id will automatically be stripped. However,
	 * older versions of CAS (i.e. CAS 2), do not automatically strip the session
	 * identifier (this is a bug on the part of the older server implementations), so an
	 * option to disable the session encoding is provided for backwards compatibility.
	 *
	 * By default, encoding is enabled.
	 */
	private boolean encodeServiceUrlWithSessionId = true;

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	@Override
	public void afterPropertiesSet() {
		Assert.hasLength(this.loginUrl, "loginUrl must be specified");
		Assert.notNull(this.serviceProperties, "serviceProperties must be specified");
		Assert.notNull(this.serviceProperties.getService(), "serviceProperties.getService() cannot be null.");
	}

	@Override
	public final void commence(final HttpServletRequest servletRequest, HttpServletResponse response,
			AuthenticationException authenticationException) throws IOException {
		String urlEncodedService = createServiceUrl(servletRequest, response);
		String redirectUrl = createRedirectUrl(urlEncodedService);
		preCommence(servletRequest, response);
		this.redirectStrategy.sendRedirect(servletRequest, response, redirectUrl);
	}

	/**
	 * Constructs a new Service Url. The default implementation relies on the CAS client
	 * to do the bulk of the work.
	 * @param request the HttpServletRequest
	 * @param response the HttpServlet Response
	 * @return the constructed service url. CANNOT be NULL.
	 */
	protected String createServiceUrl(HttpServletRequest request, HttpServletResponse response) {
		return WebUtils.constructServiceUrl(null, response, this.serviceProperties.getService(), null,
				this.serviceProperties.getArtifactParameter(), this.encodeServiceUrlWithSessionId);
	}

	/**
	 * Constructs the Url for Redirection to the CAS server. Default implementation relies
	 * on the CAS client to do the bulk of the work.
	 * @param serviceUrl the service url that should be included.
	 * @return the redirect url. CANNOT be NULL.
	 */
	protected String createRedirectUrl(String serviceUrl) {
		return CommonUtils.constructRedirectUrl(this.loginUrl, this.serviceProperties.getServiceParameter(), serviceUrl,
				this.serviceProperties.isSendRenew(), false);
	}

	/**
	 * Template method for you to do your own pre-processing before the redirect occurs.
	 * @param request the HttpServletRequest
	 * @param response the HttpServletResponse
	 */
	protected void preCommence(HttpServletRequest request, HttpServletResponse response) {

	}

	/**
	 * The enterprise-wide CAS login URL. Usually something like
	 * <code>https://www.mycompany.com/cas/login</code>.
	 * @return the enterprise-wide CAS login URL
	 */
	public final String getLoginUrl() {
		return this.loginUrl;
	}

	public final ServiceProperties getServiceProperties() {
		return this.serviceProperties;
	}

	public final void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}

	public final void setServiceProperties(ServiceProperties serviceProperties) {
		this.serviceProperties = serviceProperties;
	}

	/**
	 * Sets whether to encode the service url with the session id or not.
	 * @param encodeServiceUrlWithSessionId whether to encode the service url with the
	 * session id or not.
	 */
	public final void setEncodeServiceUrlWithSessionId(boolean encodeServiceUrlWithSessionId) {
		this.encodeServiceUrlWithSessionId = encodeServiceUrlWithSessionId;
	}

	/**
	 * Sets whether to encode the service url with the session id or not.
	 * @return whether to encode the service url with the session id or not.
	 *
	 */
	protected boolean getEncodeServiceUrlWithSessionId() {
		return this.encodeServiceUrlWithSessionId;
	}

	/**
	 * Sets the {@link RedirectStrategy} to use
	 * @param redirectStrategy the {@link RedirectStrategy} to use
	 * @since 6.3
	 */
	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		Assert.notNull(redirectStrategy, "redirectStrategy cannot be null");
		this.redirectStrategy = redirectStrategy;
	}

}
