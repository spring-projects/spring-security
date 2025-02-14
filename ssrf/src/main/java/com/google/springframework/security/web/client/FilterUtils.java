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

class FilterUtils {

	public static boolean isInternalIp(InetAddress addr) {

		if (addr.isLoopbackAddress()) {
			return true;
		}

		byte[] rawAddress = addr.getAddress();

		// there is sadly no Stream support for byte arrays
		int[] iAddr = new int[rawAddress.length];
		for (int i = 0; i < rawAddress.length; i++) {
			iAddr[i] = Byte.toUnsignedInt(rawAddress[i]);
		}

		// Ignoring Multicast addresses
		if (addr.getAddress().length == 4) {
			// IPv4 filtering
			// 10.x.x.x , 192.168.x.x , 172.16.x.x
			if (iAddr[0] == 10 ||
					(iAddr[0] == 192 && iAddr[1] == 168) ||
					(iAddr[0] == 172 && iAddr[1] == 16)) {
				return true;
			}

		} else if (addr.getAddress().length == 16) {
			// IPv6, check for Unique Local Addresses
			if (iAddr[0] == 0xfc || iAddr[0] == 0xfd) {
				return true;
			}

			// IPv4/IPv6 translation, 64:ff9b
			if (iAddr[0] == 0x00 && iAddr[1] == 0x64 && iAddr[2] == 0xff && iAddr[3] == 0x9b) {
				int[] ipv4Part = new int[]{iAddr[12], iAddr[13], iAddr[14], iAddr[15]};
				// same check as above plus a check for loopback
				if (ipv4Part[0] == 10 || ipv4Part[0] == 127 ||
						(ipv4Part[0] == 192 && ipv4Part[1] == 168) ||
						(ipv4Part[0] == 172 && ipv4Part[1] == 16)) {
					return true;
				}
			}
		}
		return false;
	}
}
