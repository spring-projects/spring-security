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
import java.util.regex.Pattern;

import org.springframework.util.Assert;

/**
 * Utility class for parsing IP addresses.
 *
 * @author Luke Taylor
 * @author Steve Riesenberg
 * @author Andrey Litvitski
 * @author Rob Winch
 * @since 7.1
 */
final class InetAddressParser {

	private static Pattern IPV4 = Pattern.compile("^\\d{1,3}(?:\\.\\d{1,3}){0,3}(?:/\\d{1,2})?$");

	/**
	 * Parses the given address string into an {@link InetAddress}.
	 * @param address the IP address string to parse
	 * @return the parsed {@link InetAddress}
	 * @throws IllegalArgumentException if the address cannot be parsed or appears to be a
	 * hostname
	 */
	static InetAddress parseAddress(String address) {
		assertNotHostName(address);
		try {
			return InetAddress.getByName(address);
		}
		catch (UnknownHostException ex) {
			throw new IllegalArgumentException("Failed to parse address '" + address + "'", ex);
		}
	}

	static void assertNotHostName(String ipAddress) {
		Assert.isTrue(isIpAddress(ipAddress),
				() -> String.format("ipAddress %s doesn't look like an IP Address. Is it a host name?", ipAddress));
	}

	private static boolean isIpAddress(String ipAddress) {
		if (!org.springframework.util.StringUtils.hasText(ipAddress)) {
			return false;
		}
		// @formatter:off
		return IPV4.matcher(ipAddress).matches()
			|| ipAddress.charAt(0) == '['
			|| ipAddress.charAt(0) == ':'
			|| Character.digit(ipAddress.charAt(0), 16) != -1
			&& ipAddress.indexOf(':') > 0;
		// @formatter:on
	}

	private InetAddressParser() {
	}

}
