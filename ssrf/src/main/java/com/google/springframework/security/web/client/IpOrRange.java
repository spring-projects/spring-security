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
package com.google.springframework.security.web.client;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Class to represent and IPv4 or IPv6 range to be used in filtering. Inspired by:
 * org.springframework.security.web.util.matcher.IpAddressMatcher.java
 */
public final class IpOrRange {

	private static final Log logger = LogFactory.getLog(IpOrRange.class);
	private final InetAddress address;
	private final int nMaskBits;
	private final String hostname;

	public IpOrRange(String addressOrRange) {
		String addressToParse;
		String originalInputAddress;

		if (addressOrRange.indexOf('/') > 0) {
			String[] addressAndMask = addressOrRange.split("/");
			originalInputAddress = addressAndMask[0];
			addressToParse = addressAndMask[0];
			this.nMaskBits = Integer.parseInt(addressAndMask[1]);
		} else {
			originalInputAddress = addressOrRange;
			addressToParse = addressOrRange;
			this.nMaskBits = -1;
		}

		if (originalInputAddress.matches(".*[a-zA-Z].*") && !originalInputAddress.contains(":")) {
			this.hostname = originalInputAddress;
		} else {
			this.hostname = null;
		}

		this.address = parseAddress(addressToParse);
	}

	private String stripWww(String host) {
		// host is expected to be non-null by callers in the matches method.
		if (host.toLowerCase().startsWith("www.")) {
			return host.substring(4);
		}
		return host;
	}

	public boolean matches(String toCheckAddressString, InetAddress toCheckInetAddress) {
		if (this.hostname != null) {
			// Check if toCheckAddressString is a hostname
			if (toCheckAddressString.matches(".*[a-zA-Z].*") && !toCheckAddressString.contains(":")) {
				String normalizedStoredHostname = stripWww(this.hostname);
				String normalizedToCheckHostname = stripWww(toCheckAddressString);
				return normalizedStoredHostname.equalsIgnoreCase(normalizedToCheckHostname);
			}
			// If this.hostname is not null, but toCheckAddressString is an IP, fall through to IP matching
		}

		// IP matching logic (either this.hostname is null, or it's a hostname but toCheckAddressString is an IP)
		if (this.nMaskBits < 0) {
			// This means this IpOrRange is a single IP address (not a range)
			if (this.address == null) { // Should not happen if constructor logic is correct
				return false;
			}
			return this.address.equals(toCheckInetAddress);
		}

		// This is a range comparison
		if (this.address == null || toCheckInetAddress == null) { // Should not happen
			return false;
		}

		byte[] remAddr = toCheckInetAddress.getAddress();
		byte[] reqAddr = this.address.getAddress();

		// Ensure address families are the same
		if (remAddr.length != reqAddr.length) {
			return false;
		}

		int nMaskFullBytes = this.nMaskBits / 8;
		byte finalByte = (byte) (0xFF00 >> (this.nMaskBits & 0x07)); // MASK for last byte

		for (int i = 0; i < nMaskFullBytes; i++) {
			if (remAddr[i] != reqAddr[i]) {
				return false;
			}
		}

		if (finalByte != 0) { // Check if the mask covers a partial byte
			return (remAddr[nMaskFullBytes] & finalByte) == (reqAddr[nMaskFullBytes] & finalByte);
		}

		// If mask is a multiple of 8, then all necessary bytes already matched
		return true;
	}

	private InetAddress parseAddress(String address) {
		try {
			InetAddress result = InetAddress.getByName(address);
			if (address.matches(".*[a-zA-Z\\-].*$") && !address.contains(":")) {
				logger.warn("Hostname '" + address + "' resolved to " + result.toString()
						+ " will be used on IP address matching");
			}
			return result;
		} catch (UnknownHostException ex) {
			throw new IllegalArgumentException(String.format("Failed to parse address '%s'", address), ex);
		}
	}

	@Override
	public String toString() {
		return "IpOrRange{" +
				"address=" + address +
				", nMaskBits=" + nMaskBits +
				'}';
	}
}
