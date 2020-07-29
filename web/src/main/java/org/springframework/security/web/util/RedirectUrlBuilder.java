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

package org.springframework.security.web.util;

import org.springframework.util.Assert;

/**
 * Internal class for building redirect URLs.
 *
 * Could probably make more use of the classes in java.net for this.
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class RedirectUrlBuilder {

	private String scheme;

	private String serverName;

	private int port;

	private String contextPath;

	private String servletPath;

	private String pathInfo;

	private String query;

	public void setScheme(String scheme) {
		if (!("http".equals(scheme) | "https".equals(scheme))) {
			throw new IllegalArgumentException("Unsupported scheme '" + scheme + "'");
		}
		this.scheme = scheme;
	}

	public void setServerName(String serverName) {
		this.serverName = serverName;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public void setContextPath(String contextPath) {
		this.contextPath = contextPath;
	}

	public void setServletPath(String servletPath) {
		this.servletPath = servletPath;
	}

	public void setPathInfo(String pathInfo) {
		this.pathInfo = pathInfo;
	}

	public void setQuery(String query) {
		this.query = query;
	}

	public String getUrl() {
		StringBuilder sb = new StringBuilder();

		Assert.notNull(this.scheme, "scheme cannot be null");
		Assert.notNull(this.serverName, "serverName cannot be null");

		sb.append(this.scheme).append("://").append(this.serverName);

		// Append the port number if it's not standard for the scheme
		if (this.port != (this.scheme.equals("http") ? 80 : 443)) {
			sb.append(":").append(this.port);
		}

		if (this.contextPath != null) {
			sb.append(this.contextPath);
		}

		if (this.servletPath != null) {
			sb.append(this.servletPath);
		}

		if (this.pathInfo != null) {
			sb.append(this.pathInfo);
		}

		if (this.query != null) {
			sb.append("?").append(this.query);
		}

		return sb.toString();
	}

}
