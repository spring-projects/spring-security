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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.Test;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link IpAddressReactiveAuthorizationManager}
 *
 * @author Guirong Hu
 */
public class IpAddressReactiveAuthorizationManagerTests {

	@Test
	public void checkWhenHasIpv6AddressThenReturnTrue() throws UnknownHostException {
		IpAddressReactiveAuthorizationManager v6manager = IpAddressReactiveAuthorizationManager
				.hasIpAddress("fe80::21f:5bff:fe33:bd68");
		boolean granted = v6manager.check(null, context("fe80::21f:5bff:fe33:bd68")).block().isGranted();
		assertThat(granted).isTrue();
	}

	@Test
	public void checkWhenHasIpv6AddressThenReturnFalse() throws UnknownHostException {
		IpAddressReactiveAuthorizationManager v6manager = IpAddressReactiveAuthorizationManager
				.hasIpAddress("fe80::21f:5bff:fe33:bd68");
		boolean granted = v6manager.check(null, context("fe80::1c9a:7cfd:29a8:a91e")).block().isGranted();
		assertThat(granted).isFalse();
	}

	@Test
	public void checkWhenHasIpv4AddressThenReturnTrue() throws UnknownHostException {
		IpAddressReactiveAuthorizationManager v4manager = IpAddressReactiveAuthorizationManager
				.hasIpAddress("192.168.1.104");
		boolean granted = v4manager.check(null, context("192.168.1.104")).block().isGranted();
		assertThat(granted).isTrue();
	}

	@Test
	public void checkWhenHasIpv4AddressThenReturnFalse() throws UnknownHostException {
		IpAddressReactiveAuthorizationManager v4manager = IpAddressReactiveAuthorizationManager
				.hasIpAddress("192.168.1.104");
		boolean granted = v4manager.check(null, context("192.168.100.15")).block().isGranted();
		assertThat(granted).isFalse();
	}

	private static AuthorizationContext context(String ipAddress) throws UnknownHostException {
		MockServerWebExchange exchange = MockServerWebExchange.builder(MockServerHttpRequest.get("/")
				.remoteAddress(new InetSocketAddress(InetAddress.getByName(ipAddress), 8080))).build();
		return new AuthorizationContext(exchange);
	}

}
