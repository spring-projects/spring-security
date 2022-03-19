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

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.Assert;

/**
 * @author Luke Taylor
 */
public abstract class AbstractRetryEntryPoint implements ChannelEntryPoint {

	protected final Log logger = LogFactory.getLog(getClass());

	private PortMapper portMapper = new PortMapperImpl();

	private PortResolver portResolver = new PortResolverImpl();

	/**
	 * The scheme ("http://" or "https://")
	 */
	private final String scheme;

	/**
	 * The standard port for the scheme (80 for http, 443 for https)
	 */
	private final int standardPort;

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public AbstractRetryEntryPoint(String scheme, int standardPort) {
		this.scheme = scheme;
		this.standardPort = standardPort;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String queryString = request.getQueryString();
		String redirectUrl = request.getRequestURI() + ((queryString != null) ? ("?" + queryString) : "");
		Integer currentPort = this.portResolver.getServerPort(request);
		Integer redirectPort = getMappedPort(currentPort);
		if (redirectPort != null) {
			boolean includePort = redirectPort != this.standardPort;
			String port = (includePort) ? (":" + redirectPort) : "";
			redirectUrl = this.scheme + request.getServerName() + port + redirectUrl;
		}
		this.logger.debug(LogMessage.format("Redirecting to: %s", redirectUrl));
		this.redirectStrategy.sendRedirect(request, response, redirectUrl);
	}

	protected abstract Integer getMappedPort(Integer mapFromPort);

	protected final PortMapper getPortMapper() {
		return this.portMapper;
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
		return this.portResolver;
	}

	/**
	 * Sets the strategy to be used for redirecting to the required channel URL. A
	 * {@code DefaultRedirectStrategy} instance will be used if not set.
	 * @param redirectStrategy the strategy instance to which the URL will be passed.
	 */
	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		Assert.notNull(redirectStrategy, "redirectStrategy cannot be null");
		this.redirectStrategy = redirectStrategy;
	}

	protected final RedirectStrategy getRedirectStrategy() {
		return this.redirectStrategy;
	}

}
