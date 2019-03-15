/*
 * Copyright 2002-2016 the original author or authors.
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

import org.springframework.security.web.*;
import org.springframework.util.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Luke Taylor
 */
public abstract class AbstractRetryEntryPoint implements ChannelEntryPoint {
	// ~ Static fields/initializers
	// =====================================================================================
	protected final Log logger = LogFactory.getLog(getClass());

	// ~ Instance fields
	// ================================================================================================

	private PortMapper portMapper = new PortMapperImpl();
	private PortResolver portResolver = new PortResolverImpl();
	/** The scheme ("http://" or "https://") */
	private final String scheme;
	/** The standard port for the scheme (80 for http, 443 for https) */
	private final int standardPort;

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	// ~ Constructors
	// ===================================================================================================

	public AbstractRetryEntryPoint(String scheme, int standardPort) {
		this.scheme = scheme;
		this.standardPort = standardPort;
	}

	// ~ Methods
	// ========================================================================================================

	public void commence(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		String queryString = request.getQueryString();
		String redirectUrl = request.getRequestURI()
				+ ((queryString == null) ? "" : ("?" + queryString));

		Integer currentPort = Integer.valueOf(portResolver.getServerPort(request));
		Integer redirectPort = getMappedPort(currentPort);

		if (redirectPort != null) {
			boolean includePort = redirectPort.intValue() != standardPort;

			redirectUrl = scheme + request.getServerName()
					+ ((includePort) ? (":" + redirectPort) : "") + redirectUrl;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Redirecting to: " + redirectUrl);
		}

		redirectStrategy.sendRedirect(request, response, redirectUrl);
	}

	protected abstract Integer getMappedPort(Integer mapFromPort);

	protected final PortMapper getPortMapper() {
		return portMapper;
	}

	public void setPortMapper(PortMapper portMapper) {
		Assert.notNull(portMapper, "portMapper cannot be null");
		this.portMapper = portMapper;
	}

	public void setPortResolver(PortResolver portResolver) {
		Assert.notNull(portResolver, "portResolver cannot be null");
		this.portResolver = portResolver;
	}

	protected final PortResolver getPortResolver() {
		return portResolver;
	}

	/**
	 * Sets the strategy to be used for redirecting to the required channel URL. A
	 * {@code DefaultRedirectStrategy} instance will be used if not set.
	 *
	 * @param redirectStrategy the strategy instance to which the URL will be passed.
	 */
	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		Assert.notNull(redirectStrategy, "redirectStrategy cannot be null");
		this.redirectStrategy = redirectStrategy;
	}

	protected final RedirectStrategy getRedirectStrategy() {
		return redirectStrategy;
	}
}
