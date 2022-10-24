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

package org.springframework.security.web.server.util.matcher;

import reactor.core.publisher.Mono;

import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Matches a request based on IP Address or subnet mask matching against the remote
 * address.
 *
 * @author Guirong Hu
 * @since 5.7
 */
public final class IpAddressServerWebExchangeMatcher implements ServerWebExchangeMatcher {

	private final IpAddressMatcher ipAddressMatcher;

	/**
	 * Takes a specific IP address or a range specified using the IP/Netmask (e.g.
	 * 192.168.1.0/24 or 202.24.0.0/14).
	 * @param ipAddress the address or range of addresses from which the request must
	 * come.
	 */
	public IpAddressServerWebExchangeMatcher(String ipAddress) {
		Assert.hasText(ipAddress, "IP address cannot be empty");
		this.ipAddressMatcher = new IpAddressMatcher(ipAddress);
	}

	@Override
	public Mono<MatchResult> matches(ServerWebExchange exchange) {
		// @formatter:off
		return Mono.justOrEmpty(exchange.getRequest().getRemoteAddress())
				.map((remoteAddress) -> remoteAddress.isUnresolved() ? remoteAddress.getHostString() : remoteAddress.getAddress().getHostAddress())
				.map(this.ipAddressMatcher::matches)
				.flatMap((matches) -> matches ? MatchResult.match() : MatchResult.notMatch())
				.switchIfEmpty(MatchResult.notMatch());
		// @formatter:on
	}

	@Override
	public String toString() {
		return "IpAddressServerWebExchangeMatcher{ipAddressMatcher=" + this.ipAddressMatcher + '}';
	}

}
