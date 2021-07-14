/*
 * Copyright 2002-2017 the original author or authors.
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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Guirong Hu
 * @since 5.6
 */
@RunWith(MockitoJUnitRunner.class)
public class IpAddressServerWebExchangeMatcherTests {

	final IpAddressServerWebExchangeMatcher v4matcher = new IpAddressServerWebExchangeMatcher("192.168.1.104");

	final IpAddressServerWebExchangeMatcher v6matcher = new IpAddressServerWebExchangeMatcher(
			"fe80::21f:5bff:fe33:bd68");

	ServerWebExchange ipv4Exchange;

	ServerWebExchange ipv6Exchange;

	@Before
	public void setUp() throws UnknownHostException {
		this.ipv4Exchange = exchange("192.168.1.104");
		this.ipv6Exchange = exchange("fe80::21f:5bff:fe33:bd68");
	}

	@Test
	public void ipv6MatcherMatchesIpv6Address() {
		ServerWebExchangeMatcher.MatchResult matches = this.v6matcher.matches(this.ipv6Exchange).block();
		assertThat(matches.isMatch()).isTrue();
	}

	@Test
	public void ipv6MatcherDoesntMatchIpv4Address() {
		ServerWebExchangeMatcher.MatchResult matches = this.v6matcher.matches(this.ipv4Exchange).block();
		assertThat(matches.isMatch()).isFalse();
	}

	@Test
	public void ipv4MatcherMatchesIpv4Address() {
		ServerWebExchangeMatcher.MatchResult matches = this.v4matcher.matches(this.ipv4Exchange).block();
		assertThat(matches.isMatch()).isTrue();
	}

	@Test
	public void ipv4SubnetMatchesCorrectly() throws UnknownHostException {
		IpAddressServerWebExchangeMatcher matcher = new IpAddressServerWebExchangeMatcher("192.168.1.0/24");
		assertThat(matcher.matches(this.ipv4Exchange).block().isMatch()).isTrue();
		matcher = new IpAddressServerWebExchangeMatcher("192.168.1.128/25");
		assertThat(matcher.matches(this.ipv4Exchange).block().isMatch()).isFalse();
		assertThat(matcher.matches(exchange("192.168.1.159")).block().isMatch()).isTrue(); // 159
																							// =
																							// 0x9
	}

	@Test
	public void ipv6RangeMatches() {
		IpAddressServerWebExchangeMatcher matcher = new IpAddressServerWebExchangeMatcher("2001:DB8::/48");
		assertThat(matcher.matches("2001:DB8:0:0:0:0:0:0")).isTrue();
		assertThat(matcher.matches("2001:DB8:0:0:0:0:0:1")).isTrue();
		assertThat(matcher.matches("2001:DB8:0:FFFF:FFFF:FFFF:FFFF:FFFF")).isTrue();
		assertThat(matcher.matches("2001:DB8:1:0:0:0:0:0")).isFalse();
	}

	// SEC-1733
	@Test
	public void zeroMaskMatchesAnything() {
		IpAddressServerWebExchangeMatcher matcher = new IpAddressServerWebExchangeMatcher("0.0.0.0/0");
		assertThat(matcher.matches("123.4.5.6")).isTrue();
		assertThat(matcher.matches("192.168.0.159")).isTrue();
		matcher = new IpAddressServerWebExchangeMatcher("192.168.0.159/0");
		assertThat(matcher.matches("123.4.5.6")).isTrue();
		assertThat(matcher.matches("192.168.0.159")).isTrue();
	}

	// SEC-2576
	@Test
	public void ipv4RequiredAddressMaskTooLongThenIllegalArgumentException() {
		String ipv4AddressWithTooLongMask = "192.168.1.104/33";
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new IpAddressServerWebExchangeMatcher(ipv4AddressWithTooLongMask))
				.withMessage(String.format("IP address %s is too short for bitmask of length %d", "192.168.1.104", 33));
	}

	// SEC-2576
	@Test
	public void ipv6RequiredAddressMaskTooLongThenIllegalArgumentException() {
		String ipv6AddressWithTooLongMask = "fe80::21f:5bff:fe33:bd68/129";
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new IpAddressServerWebExchangeMatcher(ipv6AddressWithTooLongMask))
				.withMessage(String.format("IP address %s is too short for bitmask of length %d",
						"fe80::21f:5bff:fe33:bd68", 129));
	}

	private static ServerWebExchange exchange(String ipAddress) throws UnknownHostException {
		return MockServerWebExchange.builder(MockServerHttpRequest.get("/")
				.remoteAddress(new InetSocketAddress(InetAddress.getByName(ipAddress), 8080))).build();
	}

}
