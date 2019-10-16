/*
 * Copyright 2002-2019 the original author or authors.
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

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

/**
 * Tests for {@link WebSecurityExpressionRoot}.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class WebSecurityExpressionRootTests {

	@Test
	public void ipAddressMatchesForEqualIpAddresses() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/test");
		// IPv4
		request.setRemoteAddr("192.168.1.1");
		WebSecurityExpressionRoot root = getWebSecurityExpressionRoot(request);

		assertThat(root.hasIpAddress("192.168.1.1")).isTrue();

		// IPv6 Address
		request.setRemoteAddr("fa:db8:85a3::8a2e:370:7334");
		assertThat(root.hasIpAddress("fa:db8:85a3::8a2e:370:7334")).isTrue();
	}

	@Test
	public void anyIpAddressMatchesForEqualIpAddresses() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/test");
		WebSecurityExpressionRoot root = getWebSecurityExpressionRoot(request);
		// IPv4
		String ipv4Address1 = "192.168.1.1";
		String ipv4Address2 = "127.0.0.1";

		request.setRemoteAddr("192.168.1.2");
		assertThat(root.hasAnyIpAddress(ipv4Address1, ipv4Address2)).isFalse();

		request.setRemoteAddr(ipv4Address1);
		assertThat(root.hasAnyIpAddress(ipv4Address1, ipv4Address2)).isTrue();

		request.setRemoteAddr(ipv4Address2);
		assertThat(root.hasAnyIpAddress(ipv4Address1, ipv4Address2)).isTrue();

		// IPv6 Address
		String ipv6Address1 = "fa:db8:85a3::8a2e:370:7334";
		String ipv6Address2 = "fa:db8:85a3::8a2e:370:7335";

		request.setRemoteAddr("fa:db8:85a3::8a2e:370:7333");
		assertThat(root.hasAnyIpAddress(ipv6Address1, ipv6Address2)).isFalse();

		request.setRemoteAddr(ipv6Address1);
		assertThat(root.hasAnyIpAddress(ipv6Address1, ipv6Address2)).isTrue();

		request.setRemoteAddr(ipv6Address2);
		assertThat(root.hasAnyIpAddress(ipv6Address1, ipv6Address2)).isTrue();
	}

	@Test
	public void anyIpAddressMatchesForIpAddressesRange() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/test");
		WebSecurityExpressionRoot root = getWebSecurityExpressionRoot(request);

		for (int i = 0; i < 255; i++) {
			request.setRemoteAddr("192.168.1." + i);
			assertThat(root.hasAnyIpAddress("192.168.1.0/24", "192.168.2.0/24")).isTrue();
			assertThat(root.hasAnyIpAddress("192.168.3.0/24", "192.168.4.0/24")).isFalse();
			request.setRemoteAddr("192.168.2." + i);
			assertThat(root.hasAnyIpAddress("192.168.1.0/24", "192.168.2.0/24")).isTrue();
		}
	}

	@Test
	public void addressesInIpRangeMatch() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/test");
		WebSecurityExpressionRoot root = getWebSecurityExpressionRoot(request);
		for (int i = 0; i < 255; i++) {
			request.setRemoteAddr("192.168.1." + i);
			assertThat(root.hasIpAddress("192.168.1.0/24")).isTrue();
		}

		request.setRemoteAddr("192.168.1.127");
		// 25 = FF FF FF 80
		assertThat(root.hasIpAddress("192.168.1.0/25")).isTrue();
		// encroach on the mask
		request.setRemoteAddr("192.168.1.128");
		assertThat(root.hasIpAddress("192.168.1.0/25")).isFalse();
		request.setRemoteAddr("192.168.1.255");
		assertThat(root.hasIpAddress("192.168.1.128/25")).isTrue();
		assertThat(root.hasIpAddress("192.168.1.192/26")).isTrue();
		assertThat(root.hasIpAddress("192.168.1.224/27")).isTrue();
		assertThat(root.hasIpAddress("192.168.1.240/27")).isTrue();
		assertThat(root.hasIpAddress("192.168.1.255/32")).isTrue();

		request.setRemoteAddr("202.24.199.127");
		assertThat(root.hasIpAddress("202.24.0.0/14")).isTrue();
		request.setRemoteAddr("202.25.179.135");
		assertThat(root.hasIpAddress("202.24.0.0/14")).isTrue();
		request.setRemoteAddr("202.26.179.135");
		assertThat(root.hasIpAddress("202.24.0.0/14")).isTrue();
	}

	private WebSecurityExpressionRoot getWebSecurityExpressionRoot(MockHttpServletRequest request) {
		return new WebSecurityExpressionRoot(
				mock(Authentication.class), new FilterInvocation(request,
				mock(HttpServletResponse.class), mock(FilterChain.class)));
	}

}
