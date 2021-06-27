/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.web.server.authorization;

import reactor.core.publisher.Mono;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.util.matcher.IpAddressServerWebExchangeMatcher;
import org.springframework.util.Assert;

/**
 * A {@link ReactiveAuthorizationManager}, that determines if the current request contains
 * the specified address or range of addresses
 *
 * @author Guirong Hu
 * @since 5.7
 */
public final class IpAddressReactiveAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

	private final IpAddressServerWebExchangeMatcher ipAddressExchangeMatcher;

	IpAddressReactiveAuthorizationManager(String ipAddress) {
		this.ipAddressExchangeMatcher = new IpAddressServerWebExchangeMatcher(ipAddress);
	}

	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, AuthorizationContext context) {
		return Mono.just(context.getExchange()).flatMap(this.ipAddressExchangeMatcher::matches)
				.map((matchResult) -> new AuthorizationDecision(matchResult.isMatch()));
	}

	/**
	 * Creates an instance of {@link IpAddressReactiveAuthorizationManager} with the
	 * provided IP address.
	 * @param ipAddress the address or range of addresses from which the request must
	 * @return the new instance
	 */
	public static IpAddressReactiveAuthorizationManager hasIpAddress(String ipAddress) {
		Assert.notNull(ipAddress, "This IP address is required; it must not be null");
		return new IpAddressReactiveAuthorizationManager(ipAddress);
	}

}
