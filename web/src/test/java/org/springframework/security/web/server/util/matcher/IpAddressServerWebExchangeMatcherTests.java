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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link IpAddressServerWebExchangeMatcher}
 *
 * @author Guirong Hu
 */
@ExtendWith(MockitoExtension.class)
public class IpAddressServerWebExchangeMatcherTests {

	@Test
	public void matchesWhenIpv6RangeAndIpv6AddressThenTrue() throws UnknownHostException {
		ServerWebExchange ipv6Exchange = exchange("fe80::21f:5bff:fe33:bd68");
		ServerWebExchangeMatcher.MatchResult matches = new IpAddressServerWebExchangeMatcher("fe80::21f:5bff:fe33:bd68")
				.matches(ipv6Exchange).block();
		assertThat(matches.isMatch()).isTrue();
	}

	@Test
	public void matchesWhenIpv6RangeAndIpv4AddressThenFalse() throws UnknownHostException {
		ServerWebExchange ipv4Exchange = exchange("192.168.1.104");
		ServerWebExchangeMatcher.MatchResult matches = new IpAddressServerWebExchangeMatcher("fe80::21f:5bff:fe33:bd68")
				.matches(ipv4Exchange).block();
		assertThat(matches.isMatch()).isFalse();
	}

	@Test
	public void matchesWhenIpv4RangeAndIpv4AddressThenTrue() throws UnknownHostException {
		ServerWebExchange ipv4Exchange = exchange("192.168.1.104");
		ServerWebExchangeMatcher.MatchResult matches = new IpAddressServerWebExchangeMatcher("192.168.1.104")
				.matches(ipv4Exchange).block();
		assertThat(matches.isMatch()).isTrue();
	}

	@Test
	public void matchesWhenIpv4SubnetAndIpv4AddressThenTrue() throws UnknownHostException {
		ServerWebExchange ipv4Exchange = exchange("192.168.1.104");
		IpAddressServerWebExchangeMatcher matcher = new IpAddressServerWebExchangeMatcher("192.168.1.0/24");
		assertThat(matcher.matches(ipv4Exchange).block().isMatch()).isTrue();
	}

	@Test
	public void matchesWhenIpv4SubnetAndIpv4AddressThenFalse() throws UnknownHostException {
		ServerWebExchange ipv4Exchange = exchange("192.168.1.104");
		IpAddressServerWebExchangeMatcher matcher = new IpAddressServerWebExchangeMatcher("192.168.1.128/25");
		assertThat(matcher.matches(ipv4Exchange).block().isMatch()).isFalse();
	}

	@Test
	public void matchesWhenIpv6SubnetAndIpv6AddressThenTrue() throws UnknownHostException {
		ServerWebExchange ipv6Exchange = exchange("2001:DB8:0:FFFF:FFFF:FFFF:FFFF:FFFF");
		IpAddressServerWebExchangeMatcher matcher = new IpAddressServerWebExchangeMatcher("2001:DB8::/48");
		assertThat(matcher.matches(ipv6Exchange).block().isMatch()).isTrue();
	}

	@Test
	public void matchesWhenIpv6SubnetAndIpv6AddressThenFalse() throws UnknownHostException {
		ServerWebExchange ipv6Exchange = exchange("2001:DB8:1:0:0:0:0:0");
		IpAddressServerWebExchangeMatcher matcher = new IpAddressServerWebExchangeMatcher("2001:DB8::/48");
		assertThat(matcher.matches(ipv6Exchange).block().isMatch()).isFalse();
	}

	@Test
	public void matchesWhenZeroMaskAndAnythingThenTrue() throws UnknownHostException {
		IpAddressServerWebExchangeMatcher matcher = new IpAddressServerWebExchangeMatcher("0.0.0.0/0");
		assertThat(matcher.matches(exchange("123.4.5.6")).block().isMatch()).isTrue();
		assertThat(matcher.matches(exchange("192.168.0.159")).block().isMatch()).isTrue();
		matcher = new IpAddressServerWebExchangeMatcher("192.168.0.159/0");
		assertThat(matcher.matches(exchange("123.4.5.6")).block().isMatch()).isTrue();
		assertThat(matcher.matches(exchange("192.168.0.159")).block().isMatch()).isTrue();
	}

	@Test
	public void matchesWhenIpv4UnresolvedThenTrue() throws UnknownHostException {
		ServerWebExchange ipv4Exchange = exchange("192.168.1.104", true);
		ServerWebExchangeMatcher.MatchResult matches = new IpAddressServerWebExchangeMatcher("192.168.1.104")
				.matches(ipv4Exchange).block();
		assertThat(matches.isMatch()).isTrue();
	}

	@Test
	public void matchesWhenIpv6UnresolvedThenTrue() throws UnknownHostException {
		ServerWebExchange ipv6Exchange = exchange("fe80::21f:5bff:fe33:bd68", true);
		ServerWebExchangeMatcher.MatchResult matches = new IpAddressServerWebExchangeMatcher("fe80::21f:5bff:fe33:bd68")
				.matches(ipv6Exchange).block();
		assertThat(matches.isMatch()).isTrue();
	}

	@Test
	public void constructorWhenIpv4AddressMaskTooLongThenIllegalArgumentException() {
		String ipv4AddressWithTooLongMask = "192.168.1.104/33";
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new IpAddressServerWebExchangeMatcher(ipv4AddressWithTooLongMask))
				.withMessage(String.format("IP address %s is too short for bitmask of length %d", "192.168.1.104", 33));
	}

	@Test
	public void constructorWhenIpv6AddressMaskTooLongThenIllegalArgumentException() {
		String ipv6AddressWithTooLongMask = "fe80::21f:5bff:fe33:bd68/129";
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new IpAddressServerWebExchangeMatcher(ipv6AddressWithTooLongMask))
				.withMessage(String.format("IP address %s is too short for bitmask of length %d",
						"fe80::21f:5bff:fe33:bd68", 129));
	}

	private static ServerWebExchange exchange(String ipAddress) throws UnknownHostException {
		return exchange(ipAddress, false);
	}

	private static ServerWebExchange exchange(String ipAddress, boolean unresolved) throws UnknownHostException {
		return MockServerWebExchange.builder(MockServerHttpRequest.get("/")
				.remoteAddress(unresolved ? InetSocketAddress.createUnresolved(ipAddress, 8080)
						: new InetSocketAddress(InetAddress.getByName(ipAddress), 8080)))
				.build();
	}

}
