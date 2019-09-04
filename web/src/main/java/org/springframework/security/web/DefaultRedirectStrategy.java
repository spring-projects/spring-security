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
package org.springframework.security.web;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Simple implementation of <tt>RedirectStrategy</tt> which is the default used throughout
 * the framework.
 *
 * @author Luke Taylor
 * @author Josh Cummings
 * @since 3.0
 */
public class DefaultRedirectStrategy implements RedirectStrategy {

	protected final Log logger = LogFactory.getLog(getClass());

	private boolean contextRelative;
	private boolean hostRelative = true;

	/**
	 * Redirects the response to the supplied URL.
	 * <p>
	 * If <tt>contextRelative</tt> is set, the redirect value will be the value after the
	 * request context path. Note that this will result in the loss of protocol
	 * information (HTTP or HTTPS), so will cause problems if a redirect is being
	 * performed to change to HTTPS, for example.
	 */
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response,
			String url) throws IOException {
		String redirectUrl = calculateRedirectUrl(request.getContextPath(), url);
		redirectUrl = response.encodeRedirectURL(redirectUrl);

		if (logger.isDebugEnabled()) {
			logger.debug("Redirecting to '" + redirectUrl + "'");
		}

		response.sendRedirect(redirectUrl);
	}

	protected String calculateRedirectUrl(String contextPath, String url) {
		if (!UrlUtils.isAbsoluteUrl(url)) {
			if (isContextRelative()) {
				return url;
			}
			else {
				return contextPath + url;
			}
		}

		// Full URL, including http(s)://
		boolean hostRelative = this.hostRelative;
		boolean contextRelative = isContextRelative();

		if (!hostRelative && !contextRelative) {
			return url;
		}

		UriComponents components = UriComponentsBuilder
				.fromHttpUrl(url).build();

		String path = components.getPath();
		if (contextRelative) {
			path = path.substring(path.indexOf(contextPath) + contextPath.length());
			if (path.length() > 1 && path.charAt(0) == '/') {
				path = path.substring(1);
			}
		}

		return UriComponentsBuilder
				.fromPath(path)
				.query(components.getQuery())
				.build().toString();
	}

	/**
	 * If <tt>true</tt>, causes any redirection URLs to be calculated minus the authority
	 * (defaults to <tt>true</tt>).
	 */
	public void setHostRelative(boolean hostRelative) {
		this.hostRelative = hostRelative;
	}

	/**
	 * If <tt>true</tt>, causes any redirection URLs to be calculated minus the authority
	 * and context path (defaults to <tt>false</tt>).
	 */
	public void setContextRelative(boolean useRelativeContext) {
		this.contextRelative = useRelativeContext;
	}

	/**
	 * Returns <tt>true</tt>, if the redirection URL should be calculated
	 * minus the protocol and context path (defaults to <tt>false</tt>).
	 */
	protected boolean isContextRelative() {
		return contextRelative;
	}
}
