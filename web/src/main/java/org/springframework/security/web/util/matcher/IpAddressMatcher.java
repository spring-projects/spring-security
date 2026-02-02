/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.util.matcher;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;

/**
 * Matches a request based on IP Address or subnet mask matching against the remote
 * address.
 * <p>
 * Both IPv6 and IPv4 addresses are supported, but a matcher which is configured with an
 * IPv4 address will never match a request which returns an IPv6 address, and vice-versa.
 *
 * @author Luke Taylor
 * @author Steve Riesenberg
 * @author Andrey Litvitski
 * @since 3.0.2
 */
public final class IpAddressMatcher implements RequestMatcher {

	private final InetAddressMatcher matcher;

	/**
	 * Takes a specific IP address or a range specified using the IP/Netmask (e.g.
	 * 192.168.1.0/24 or 202.24.0.0/14).
	 * @param ipAddress the address or range of addresses from which the request must
	 * come.
	 */
	public IpAddressMatcher(String ipAddress) {
		this.matcher = new IpInetAddressMatcher(ipAddress);
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return this.matcher.matches(request.getRemoteAddr());
	}

	/**
	 * Checks if the given IP address string matches the configured address pattern.
	 * @param ipAddress the IP address string to check (may be {@code null})
	 * @return {@code true} if the address matches, {@code false} otherwise
	 */
	public boolean matches(@Nullable String ipAddress) {
		return this.matcher.matches(ipAddress);
	}

	@Override
	public String toString() {
		return this.matcher.toString();
	}

}
