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

import java.net.InetAddress;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link IpInetAddressMatcher}.
 *
 * @author Rob Winch
 */
class IpInetAddressMatcherTests {

	@Test
	void constructorWhenNullIpAddressThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new IpInetAddressMatcher(null))
			.withMessage("ipAddress cannot be empty");
	}

	@Test
	void constructorWhenEmptyIpAddressThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new IpInetAddressMatcher(""))
			.withMessage("ipAddress cannot be empty");
	}

	@Test
	void constructorWhenHostnameThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new IpInetAddressMatcher("example.com"))
			.withMessageContaining("doesn't look like an IP Address");
	}

	@Test
	void matchesWhenIpv4ExactMatchThenReturnsTrue() throws Exception {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("192.168.1.1");
		assertThat(matcher.matches(InetAddress.getByName("192.168.1.1"))).isTrue();
	}

	@Test
	void matchesWhenIpv4NoMatchThenReturnsFalse() throws Exception {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("192.168.1.1");
		assertThat(matcher.matches(InetAddress.getByName("192.168.1.2"))).isFalse();
	}

	@Test
	void matchesWhenIpv6ExactMatchThenReturnsTrue() throws Exception {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("fe80::21f:5bff:fe33:bd68");
		assertThat(matcher.matches(InetAddress.getByName("fe80::21f:5bff:fe33:bd68"))).isTrue();
	}

	@Test
	void matchesWhenIpv6NoMatchThenReturnsFalse() throws Exception {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("fe80::21f:5bff:fe33:bd68");
		assertThat(matcher.matches(InetAddress.getByName("fe80::21f:5bff:fe33:bd69"))).isFalse();
	}

	@Test
	void matchesWhenIpv4WithCidrMatchesSubnetThenReturnsTrue() throws Exception {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("192.168.1.0/24");
		assertThat(matcher.matches(InetAddress.getByName("192.168.1.1"))).isTrue();
		assertThat(matcher.matches(InetAddress.getByName("192.168.1.255"))).isTrue();
	}

	@Test
	void matchesWhenIpv4WithCidrOutsideSubnetThenReturnsFalse() throws Exception {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("192.168.1.0/24");
		assertThat(matcher.matches(InetAddress.getByName("192.168.2.1"))).isFalse();
		assertThat(matcher.matches(InetAddress.getByName("192.168.0.255"))).isFalse();
	}

	@Test
	void matchesWhenIpv6WithCidrMatchesSubnetThenReturnsTrue() throws Exception {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("2001:db8::/48");
		assertThat(matcher.matches(InetAddress.getByName("2001:db8:0:0:0:0:0:0"))).isTrue();
		assertThat(matcher.matches(InetAddress.getByName("2001:db8:0:ffff:ffff:ffff:ffff:ffff"))).isTrue();
	}

	@Test
	void matchesWhenIpv6WithCidrOutsideSubnetThenReturnsFalse() throws Exception {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("2001:db8::/48");
		assertThat(matcher.matches(InetAddress.getByName("2001:db8:1:0:0:0:0:0"))).isFalse();
	}

	@Test
	void matchesWhenIpv4AndIpv6AddressThenReturnsFalse() throws Exception {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("192.168.1.1");
		assertThat(matcher.matches(InetAddress.getByName("fe80::21f:5bff:fe33:bd68"))).isFalse();
	}

	@Test
	void matchesWhenIpv6AndIpv4AddressThenReturnsFalse() throws Exception {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("fe80::21f:5bff:fe33:bd68");
		assertThat(matcher.matches(InetAddress.getByName("192.168.1.1"))).isFalse();
	}

	@Test
	void matchesWhenStringIpv4MatchThenReturnsTrue() {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("192.168.1.1");
		assertThat(matcher.matches("192.168.1.1")).isTrue();
	}

	@Test
	void matchesWhenStringIpv4NoMatchThenReturnsFalse() {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("192.168.1.1");
		assertThat(matcher.matches("192.168.1.2")).isFalse();
	}

	@Test
	void matchesWhenStringNullThenReturnsFalse() {
		IpInetAddressMatcher matcher = new IpInetAddressMatcher("192.168.1.1");
		assertThat(matcher.matches((String) null)).isFalse();
	}

}
