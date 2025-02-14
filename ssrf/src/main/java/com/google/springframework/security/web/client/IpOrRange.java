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

	public IpOrRange(String addressOrRange) {
		if (addressOrRange.indexOf('/') > 0) {
			String[] addressAndMask = addressOrRange.split("/");
			address = parseAddress(addressAndMask[0]);
			this.nMaskBits = Integer.parseInt(addressAndMask[1]);
		} else {
			this.nMaskBits = -1;
			address = parseAddress(addressOrRange);
		}
	}

	public boolean matches(InetAddress toCheck) {

		if (this.nMaskBits < 0) {
			return toCheck.equals(this.address);
		}
		byte[] remAddr = toCheck.getAddress();
		byte[] reqAddr = this.address.getAddress();
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
