/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.access.channel;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Ensures a web request is delivered over the required channel.
 * <p>
 * Internally uses a {@link FilterInvocation} to represent the request, allowing a
 * {@code FilterInvocationSecurityMetadataSource} to be used to lookup the attributes
 * which apply.
 * <p>
 * Delegates the actual channel security decisions and necessary actions to the configured
 * {@link ChannelDecisionManager}. If a response is committed by the
 * {@code ChannelDecisionManager}, the filter chain will not proceed.
 * <p>
 * The most common usage is to ensure that a request takes place over HTTPS, where the
 * {@link ChannelDecisionManagerImpl} is configured with a {@link SecureChannelProcessor}
 * and an {@link InsecureChannelProcessor}. A typical configuration would be
 *
 * <pre>
 *
 * &lt;bean id="channelProcessingFilter" class="org.springframework.security.web.access.channel.ChannelProcessingFilter"&gt;
 *   &lt;property name="channelDecisionManager" ref="channelDecisionManager"/&gt;
 *   &lt;property name="securityMetadataSource"&gt;
 *     &lt;security:filter-security-metadata-source request-matcher="regex"&gt;
 *       &lt;security:intercept-url pattern="\A/secure/.*\Z" access="REQUIRES_SECURE_CHANNEL"/&gt;
 *       &lt;security:intercept-url pattern="\A/login.jsp.*\Z" access="REQUIRES_SECURE_CHANNEL"/&gt;
 *       &lt;security:intercept-url pattern="\A/.*\Z" access="ANY_CHANNEL"/&gt;
 *     &lt;/security:filter-security-metadata-source&gt;
 *   &lt;/property&gt;
 * &lt;/bean&gt;
 *
 * &lt;bean id="channelDecisionManager" class="org.springframework.security.web.access.channel.ChannelDecisionManagerImpl"&gt;
 *   &lt;property name="channelProcessors"&gt;
 *     &lt;list&gt;
 *     &lt;ref bean="secureChannelProcessor"/&gt;
 *     &lt;ref bean="insecureChannelProcessor"/&gt;
 *     &lt;/list&gt;
 *   &lt;/property&gt;
 * &lt;/bean&gt;
 *
 * &lt;bean id="secureChannelProcessor"
 *   class="org.springframework.security.web.access.channel.SecureChannelProcessor"/&gt;
 * &lt;bean id="insecureChannelProcessor"
 *   class="org.springframework.security.web.access.channel.InsecureChannelProcessor"/&gt;
 *
 * </pre>
 *
 * which would force the login form and any access to the {@code /secure} path to be made
 * over HTTPS.
 *
 * @author Ben Alex
 */
public class ChannelProcessingFilter extends GenericFilterBean {

	// ~ Instance fields
	// ================================================================================================

	private ChannelDecisionManager channelDecisionManager;

	private FilterInvocationSecurityMetadataSource securityMetadataSource;

	// ~ Methods
	// ========================================================================================================

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.securityMetadataSource, "securityMetadataSource must be specified");
		Assert.notNull(this.channelDecisionManager, "channelDecisionManager must be specified");

		Collection<ConfigAttribute> attrDefs = this.securityMetadataSource.getAllConfigAttributes();

		if (attrDefs == null) {
			if (this.logger.isWarnEnabled()) {
				this.logger.warn(
						"Could not validate configuration attributes as the FilterInvocationSecurityMetadataSource did "
								+ "not return any attributes");
			}

			return;
		}

		Set<ConfigAttribute> unsupportedAttributes = new HashSet<>();

		for (ConfigAttribute attr : attrDefs) {
			if (!this.channelDecisionManager.supports(attr)) {
				unsupportedAttributes.add(attr);
			}
		}

		if (unsupportedAttributes.size() == 0) {
			if (this.logger.isInfoEnabled()) {
				this.logger.info("Validated configuration attributes");
			}
		}
		else {
			throw new IllegalArgumentException("Unsupported configuration attributes: " + unsupportedAttributes);
		}
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		FilterInvocation fi = new FilterInvocation(request, response, chain);
		Collection<ConfigAttribute> attr = this.securityMetadataSource.getAttributes(fi);

		if (attr != null) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Request: " + fi.toString() + "; ConfigAttributes: " + attr);
			}

			this.channelDecisionManager.decide(fi, attr);

			if (fi.getResponse().isCommitted()) {
				return;
			}
		}

		chain.doFilter(request, response);
	}

	protected ChannelDecisionManager getChannelDecisionManager() {
		return this.channelDecisionManager;
	}

	protected FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
		return this.securityMetadataSource;
	}

	public void setChannelDecisionManager(ChannelDecisionManager channelDecisionManager) {
		this.channelDecisionManager = channelDecisionManager;
	}

	public void setSecurityMetadataSource(
			FilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource) {
		this.securityMetadataSource = filterInvocationSecurityMetadataSource;
	}

}
