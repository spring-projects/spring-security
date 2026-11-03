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

package org.springframework.security.web;

import java.util.Locale;

import jakarta.servlet.ServletRequest;
import org.jspecify.annotations.Nullable;

/**
 * <code>PortMapper</code> implementations provide callers with information about which
 * HTTP ports are associated with which HTTPS ports on the system, and vice versa.
 *
 * @author Ben Alex
 */
public interface PortMapper {

	/**
	 * Locates the HTTP port associated with the specified HTTPS port.
	 * <P>
	 * Returns <code>null</code> if unknown.
	 * </p>
	 * @param httpsPort
	 * @return the HTTP port or <code>null</code> if unknown
	 */
	@Nullable Integer lookupHttpPort(Integer httpsPort);

	/**
	 * Locates the HTTPS port associated with the specified HTTP port.
	 * <P>
	 * Returns <code>null</code> if unknown.
	 * </p>
	 * @param httpPort
	 * @return the HTTPS port or <code>null</code> if unknown
	 */
	@Nullable Integer lookupHttpsPort(Integer httpPort);

	/**
	 * Get server port from request and automatically apply the configured mapping.
	 * @param request ServletRequest
	 * @return the mapped port
	 */
	default Integer getServerPort(ServletRequest request) {
		int serverPort = request.getServerPort();
		String scheme = request.getScheme().toLowerCase(Locale.ENGLISH);
		Integer mappedPort = null;
		if ("http".equals(scheme)) {
			mappedPort = lookupHttpPort(serverPort);
		}
		else if ("https".equals(scheme)) {
			mappedPort = lookupHttpsPort(serverPort);
		}
		return (mappedPort != null) ? mappedPort : serverPort;
	}

}
