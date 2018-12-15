/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.StringUtils;

/**
 * Matches a request based on IP Address or subnet mask matching against the remote
 * address.
 * <p>
 * Both IPv6 and IPv4 addresses are supported, but a matcher which is configured with an
 * IPv4 address will never match a request which returns an IPv6 address, and vice-versa.
 *
 * @author Luke Taylor
 * @since 3.0.2
 */
public final class IpAddressMatcher extends AbstractRequestMatcher {
	private final int nMaskBits;
	private final InetAddress requiredAddress;

	/**
	 * Takes a specific IP address or a range specified using the IP/Netmask (e.g.
	 * 192.168.1.0/24 or 202.24.0.0/14).
	 *
	 * @param ipAddress the address or range of addresses from which the request must
	 * come.
	 */
	public IpAddressMatcher(String ipAddress) {

		if (ipAddress.indexOf('/') > 0) {
			String[] addressAndMask = StringUtils.split(ipAddress, "/");
			ipAddress = addressAndMask[0];
			nMaskBits = Integer.parseInt(addressAndMask[1]);
		}
		else {
			nMaskBits = -1;
		}
		requiredAddress = parseAddress(ipAddress);
	}

	public boolean matches(HttpServletRequest request) {
		return matches(request.getRemoteAddr());
	}

	public boolean matches(String address) {
		InetAddress remoteAddress = parseAddress(address);

		if (!requiredAddress.getClass().equals(remoteAddress.getClass())) {
			return false;
		}

		if (nMaskBits < 0) {
			return remoteAddress.equals(requiredAddress);
		}

		byte[] remAddr = remoteAddress.getAddress();
		byte[] reqAddr = requiredAddress.getAddress();

		int oddBits = nMaskBits % 8;
		int nMaskBytes = nMaskBits / 8 + (oddBits == 0 ? 0 : 1);
		byte[] mask = new byte[nMaskBytes];

		Arrays.fill(mask, 0, oddBits == 0 ? mask.length : mask.length - 1, (byte) 0xFF);

		if (oddBits != 0) {
			int finalByte = (1 << oddBits) - 1;
			finalByte <<= 8 - oddBits;
			mask[mask.length - 1] = (byte) finalByte;
		}

		// System.out.println("Mask is " + new sun.misc.HexDumpEncoder().encode(mask));

		for (int i = 0; i < mask.length; i++) {
			if ((remAddr[i] & mask[i]) != (reqAddr[i] & mask[i])) {
				return false;
			}
		}

		return true;
	}

	private InetAddress parseAddress(String address) {
		try {
			return InetAddress.getByName(address);
		}
		catch (UnknownHostException e) {
			throw new IllegalArgumentException("Failed to parse address" + address, e);
		}
	}
}
