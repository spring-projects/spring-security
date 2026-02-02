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
import java.net.UnknownHostException;
import java.util.Objects;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Implementation of {@link InetAddressMatcher} that matches IP addresses with support for
 * CIDR notation (e.g., 192.168.1.0/24).
 * <p>
 * Both IPv4 and IPv6 addresses are supported. The matcher can be configured with either a
 * specific IP address or a subnet using CIDR notation.
 *
 * @author Rossen Stoyanchev
 * @author Gábor Vaspöri
 * @author Kian Jamali
 * @author Rob Winch
 * @since 7.1
 */
final class IpInetAddressMatcher implements InetAddressMatcher {

	private static final Log logger = LogFactory.getLog(IpAddressMatcher.class);

	private final InetAddress requiredAddress;

	private final int nMaskBits;

	IpInetAddressMatcher(String ipAddress) {
		Assert.hasText(ipAddress, "ipAddress cannot be empty");
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
		this.requiredAddress = InetAddressParser.parseAddress(requiredAddress);
		this.nMaskBits = nMaskBits;
		Assert.isTrue(this.requiredAddress.getAddress().length * 8 >= this.nMaskBits, () -> String
			.format("IP address %s is too short for bitmask of length %d", requiredAddress, this.nMaskBits));
	}

	private static InetAddress parse(String address) {
		try {
			InetAddress result = InetAddress.getByName(address);
			if (address.matches(".*[a-zA-Z\\-].*$") && !address.contains(":")) {
				logger.warn("Hostname '" + address + "' resolved to " + result.toString()
						+ " will be used on IP address matching");
			}
			return result;
		}
		catch (UnknownHostException ex) {
			throw new IllegalArgumentException(String.format("Failed to parse address '%s'", address), ex);
		}
	}

	@Override
	public boolean matches(InetAddress toCheck) {
		if (this.nMaskBits < 0) {
			return toCheck.equals(this.requiredAddress);
		}
		byte[] remAddr = toCheck.getAddress();
		byte[] reqAddr = this.requiredAddress.getAddress();
		int nMaskFullBytes = this.nMaskBits / 8;
		byte finalByte = (byte) (0xFF00 >> (this.nMaskBits & 0x07));
		for (int i = 0; i < nMaskFullBytes; i++) {
			if (remAddr[i] != reqAddr[i]) {
				return false;
			}
		}
		if (finalByte != 0) {
			return (remAddr[nMaskFullBytes] & finalByte) == (reqAddr[nMaskFullBytes] & finalByte);
		}
		return true;
	}

	@Override
	public String toString() {
		String hostAddress = this.requiredAddress.getHostAddress();
		return (this.nMaskBits < 0) ? "IpAddress [" + hostAddress + "]"
				: "IpAddress [" + hostAddress + "/" + this.nMaskBits + "]";
	}

}
