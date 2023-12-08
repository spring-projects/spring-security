/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.access;

import java.util.function.Supplier;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.util.Assert;

/**
 * A {@link AuthorizationManager}, that determines if the current request contains the
 * specified address or range of addresses
 *
 * @author brunodmartins
 * @since 6.3
 */
public final class IpAddressAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

	private final IpAddressMatcher ipAddressMatcher;

	IpAddressAuthorizationManager(String ipAddress) {
		this.ipAddressMatcher = new IpAddressMatcher(ipAddress);
	}

	/**
	 * Creates an instance of {@link IpAddressAuthorizationManager} with the provided IP
	 * address.
	 * @param ipAddress the address or range of addresses from which the request must
	 * @return the new instance
	 */
	public static IpAddressAuthorizationManager hasIpAddress(String ipAddress) {
		Assert.notNull(ipAddress, "ipAddress cannot be null");
		return new IpAddressAuthorizationManager(ipAddress);
	}

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication,
			RequestAuthorizationContext requestAuthorizationContext) {
		return new AuthorizationDecision(
				this.ipAddressMatcher.matcher(requestAuthorizationContext.getRequest()).isMatch());
	}

}
