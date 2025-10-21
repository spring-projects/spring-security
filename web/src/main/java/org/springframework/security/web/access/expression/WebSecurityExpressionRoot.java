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
import org.jspecify.annotations.Nullable;

import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

/**
 * @author Luke Taylor
 * @author Evgeniy Cheban
 * @author Steve Riesenberg
 * @since 3.0
 */
public class WebSecurityExpressionRoot extends SecurityExpressionRoot<RequestAuthorizationContext> {

	/**
	 * Allows direct access to the request object
	 */
	public final HttpServletRequest request;

	/**
	 * @deprecated Use
	 * {@link #WebSecurityExpressionRoot(Supplier, RequestAuthorizationContext)} instead
	 */
	@Deprecated(since = "7.0")
	public WebSecurityExpressionRoot(@Nullable Authentication a, FilterInvocation fi) {
		this(() -> a, new RequestAuthorizationContext(fi.getRequest()));
	}

	/**
	 * Creates an instance for the given {@link Supplier} of the {@link Authentication}
	 * and {@link HttpServletRequest}.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to use
	 * @param request the {@link HttpServletRequest} to use
	 * @since 5.8
	 * @deprecated Use
	 * {@link #WebSecurityExpressionRoot(Supplier, RequestAuthorizationContext)} instead
	 */
	@Deprecated(since = "7.0")
	@SuppressWarnings("NullAway") // https://github.com/uber/NullAway/issues/1246
	public WebSecurityExpressionRoot(Supplier<? extends @Nullable Authentication> authentication,
			HttpServletRequest request) {
		super(authentication, new RequestAuthorizationContext(request));
		this.request = request;
	}

	/**
	 * Creates an instance for the given {@link Supplier} of the {@link Authentication}
	 * and {@link HttpServletRequest}.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to use
	 * @param context the {@link RequestAuthorizationContext} to use
	 * @since 7.0
	 */
	public WebSecurityExpressionRoot(Supplier<? extends @Nullable Authentication> authentication,
			RequestAuthorizationContext context) {
		super(authentication, context);
		this.request = context.getRequest();
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
