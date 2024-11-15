/*
 * Copyright 2002-2024 the original author or authors.
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
import java.net.UnknownHostException;
import java.util.Objects;
import java.util.regex.Pattern;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Matches a request based on IP Address or subnet mask matching against the remote
 * address.
 * <p>
 * Both IPv6 and IPv4 addresses are supported, but a matcher which is configured with an
 * IPv4 address will never match a request which returns an IPv6 address, and vice-versa.
 *
 * @author Luke Taylor
 * @author Steve Riesenberg
 * @since 3.0.2
 */
public final class IpAddressMatcher implements RequestMatcher {

	private static Pattern IPV4 = Pattern.compile("\\d{0,3}.\\d{0,3}.\\d{0,3}.\\d{0,3}(/\\d{0,3})?");

	private final InetAddress requiredAddress;

	private final int nMaskBits;

	/**
	 * Takes a specific IP address or a range specified using the IP/Netmask (e.g.
	 * 192.168.1.0/24 or 202.24.0.0/14).
	 * @param ipAddress the address or range of addresses from which the request must
	 * come.
	 */
	public IpAddressMatcher(String ipAddress) {
		Assert.hasText(ipAddress, "ipAddress cannot be empty");
		assertNotHostName(ipAddress);

		String requiredAddress;
		int nMaskBits;
		if (ipAddress.indexOf('/') > 0) {
			String[] parts = Objects.requireNonNull(StringUtils.split(ipAddress, "/"));
			requiredAddress = parts[0];
			nMaskBits = Integer.parseInt(parts[1]);
		}
		else {
			requiredAddress = ipAddress;
			nMaskBits = -1;
		}
		this.requiredAddress = parseAddress(requiredAddress);
		this.nMaskBits = nMaskBits;
		Assert.isTrue(this.requiredAddress.getAddress().length * 8 >= this.nMaskBits, () -> String
			.format("IP address %s is too short for bitmask of length %d", requiredAddress, this.nMaskBits));
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return matches(request.getRemoteAddr());
	}

	public boolean matches(String ipAddress) {
		// Do not match null or blank address
		if (!StringUtils.hasText(ipAddress)) {
			return false;
		}

		assertNotHostName(ipAddress);
		InetAddress remoteAddress = parseAddress(ipAddress);
		if (!this.requiredAddress.getClass().equals(remoteAddress.getClass())) {
			return false;
		}
		if (this.nMaskBits < 0) {
			return remoteAddress.equals(this.requiredAddress);
		}
		byte[] remAddr = remoteAddress.getAddress();
		byte[] reqAddr = this.requiredAddress.getAddress();
		int nMaskFullBytes = this.nMaskBits / 8;
		for (int i = 0; i < nMaskFullBytes; i++) {
			if (remAddr[i] != reqAddr[i]) {
				return false;
			}
		}
		byte finalByte = (byte) (0xFF00 >> (this.nMaskBits & 0x07));
		if (finalByte != 0) {
			return (remAddr[nMaskFullBytes] & finalByte) == (reqAddr[nMaskFullBytes] & finalByte);
		}
		return true;
	}

	private static void assertNotHostName(String ipAddress) {
		Assert.isTrue(isIpAddress(ipAddress),
				() -> String.format("ipAddress %s doesn't look like an IP Address. Is it a host name?", ipAddress));
	}

	private static boolean isIpAddress(String ipAddress) {
		// @formatter:off
		return IPV4.matcher(ipAddress).matches()
			|| ipAddress.charAt(0) == '['
			|| ipAddress.charAt(0) == ':'
			|| Character.digit(ipAddress.charAt(0), 16) != -1
			&& ipAddress.indexOf(':') > 0;
		// @formatter:on
	}

	private InetAddress parseAddress(String address) {
		try {
			return InetAddress.getByName(address);
		}
		catch (UnknownHostException ex) {
			throw new IllegalArgumentException("Failed to parse address '" + address + "'", ex);
		}
	}

}
