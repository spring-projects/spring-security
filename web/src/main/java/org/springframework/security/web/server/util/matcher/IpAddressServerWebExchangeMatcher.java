/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.security.web.util.matcher.InetAddressMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Matches a request based on IP Address or subnet mask matching against the remote
 * address.
 *
 * @author Guirong Hu
 * @since 5.6
 */
public class IpAddressServerWebExchangeMatcher implements ServerWebExchangeMatcher {

	private final InetAddressMatcher matcher;

	public IpAddressServerWebExchangeMatcher(String ipAddress) {
		Assert.notNull(ipAddress, "IP address cannot be null");
		this.matcher = new InetAddressMatcher(ipAddress);
	}

	@Override
	public Mono<MatchResult> matches(ServerWebExchange exchange) {
		return Mono.justOrEmpty(exchange.getRequest().getRemoteAddress())
				.map((remoteAddress) -> remoteAddress.getAddress().getHostAddress()).map(this::matches)
				.flatMap((matches) -> matches ? MatchResult.match() : MatchResult.notMatch())
				.switchIfEmpty(MatchResult.notMatch());
	}

	public boolean matches(String address) {
		return this.matcher.matches(address);
	}

}
