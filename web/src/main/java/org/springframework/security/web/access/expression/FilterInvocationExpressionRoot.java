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

package org.springframework.security.web.access.expression;

import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

/**
 * @author Steve Riesenberg
 * @since 7.0
 */
final class FilterInvocationExpressionRoot extends SecurityExpressionRoot<FilterInvocation> {

	/**
	 * Allows direct access to the request object
	 */
	public final HttpServletRequest request;

	/**
	 * Creates an instance for the given {@link Supplier} of the {@link Authentication}
	 * and {@link HttpServletRequest}.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to use
	 * @param fi the {@link FilterInvocation} to use
	 */
	FilterInvocationExpressionRoot(Supplier<Authentication> authentication, FilterInvocation fi) {
		super(authentication, fi);
		this.request = fi.getRequest();
	}

	/**
	 * Takes a specific IP address or a range using the IP/Netmask (e.g. 192.168.1.0/24 or
	 * 202.24.0.0/14).
	 * @param ipAddress the address or range of addresses from which the request must
	 * come.
	 * @return true if the IP address of the current request is in the required range.
	 */
	public boolean hasIpAddress(String ipAddress) {
		IpAddressMatcher matcher = new IpAddressMatcher(ipAddress);
		return matcher.matches(this.request);
	}

}
