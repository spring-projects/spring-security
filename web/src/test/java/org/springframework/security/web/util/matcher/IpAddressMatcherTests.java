package org.springframework.security.web.util.matcher;

import static org.assertj.core.api.Assertions.*;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

/**
 * @author Luke Taylor
 */
public class IpAddressMatcherTests {
	final IpAddressMatcher v6matcher = new IpAddressMatcher("fe80::21f:5bff:fe33:bd68");
	final IpAddressMatcher v4matcher = new IpAddressMatcher("192.168.1.104");
	MockHttpServletRequest ipv4Request = new MockHttpServletRequest();
	MockHttpServletRequest ipv6Request = new MockHttpServletRequest();

	@Before
	public void setup() {
		ipv6Request.setRemoteAddr("fe80::21f:5bff:fe33:bd68");
		ipv4Request.setRemoteAddr("192.168.1.104");
	}

	@Test
	public void ipv6MatcherMatchesIpv6Address() {
		assertThat(v6matcher.matches(ipv6Request)).isTrue();
	}

	@Test
	public void ipv6MatcherDoesntMatchIpv4Address() {
		assertThat(v6matcher.matches(ipv4Request)).isFalse();
	}

	@Test
	public void ipv4MatcherMatchesIpv4Address() {
		assertThat(v4matcher.matches(ipv4Request)).isTrue();
	}

	@Test
	public void ipv4SubnetMatchesCorrectly() throws Exception {
		IpAddressMatcher matcher = new IpAddressMatcher("192.168.1.0/24");
		assertThat(matcher.matches(ipv4Request)).isTrue();
		matcher = new IpAddressMatcher("192.168.1.128/25");
		assertThat(matcher.matches(ipv4Request)).isFalse();
		ipv4Request.setRemoteAddr("192.168.1.159"); // 159 = 0x9f
		assertThat(matcher.matches(ipv4Request)).isTrue();
	}

	@Test
	public void ipv6RangeMatches() throws Exception {
		IpAddressMatcher matcher = new IpAddressMatcher("2001:DB8::/48");

		assertThat(matcher.matches("2001:DB8:0:0:0:0:0:0")).isTrue();
		assertThat(matcher.matches("2001:DB8:0:0:0:0:0:1")).isTrue();
		assertThat(matcher.matches("2001:DB8:0:FFFF:FFFF:FFFF:FFFF:FFFF")).isTrue();
		assertThat(matcher.matches("2001:DB8:1:0:0:0:0:0")).isFalse();
	}

	// SEC-1733
	@Test
	public void zeroMaskMatchesAnything() throws Exception {
		IpAddressMatcher matcher = new IpAddressMatcher("0.0.0.0/0");

		assertThat(matcher.matches("123.4.5.6")).isTrue();
		assertThat(matcher.matches("192.168.0.159")).isTrue();

		matcher = new IpAddressMatcher("192.168.0.159/0");
		assertThat(matcher.matches("123.4.5.6")).isTrue();
		assertThat(matcher.matches("192.168.0.159")).isTrue();
	}
}
