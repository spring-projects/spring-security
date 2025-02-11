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

import static java.util.stream.Collectors.joining;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

class ListedSsrfProtectionFilter implements SsrfProtectionFilter {

	/**
	 * FilterMode enum to make usage more intuitive ( practically this is just a bool )
	 */
	public enum FilterMode {
		BLOCK_LIST,
		ALLOW_LIST,
	}

	private List<IpOrRange> matchingRules;

	private FilterMode mode;

	public ListedSsrfProtectionFilter(List<IpOrRange> addressList, FilterMode mode) {
		this.matchingRules = addressList;
		this.mode = mode;
	}

	@Override
	public InetAddress[] filterAddresses(InetAddress[] addresses) throws HostBlockedException {
		List<InetAddress> result = new ArrayList<>(addresses.length);

		outerLoop:
		for (InetAddress addr : addresses) {
			if (mode == FilterMode.BLOCK_LIST) {
				for (IpOrRange ipOrRange : matchingRules) {
					if (ipOrRange.matches(addr)) {
						continue outerLoop;
					}
				}
				result.add(addr);
			} else if (mode == FilterMode.ALLOW_LIST) {
				for (IpOrRange ipOrRange : matchingRules) {
					if (ipOrRange.matches(addr)) {
						result.add(addr);
						continue outerLoop;
					}
				}
			}
		}

		if (result.size() == 0) {
			String addrFmt = Arrays.stream(addresses).map(InetAddress::toString).collect(joining(", "));
			throw new HostBlockedException(
					"The following address(es) were blocked due to violating " + mode.name() + " policy: " + addrFmt);
		}

		return result.toArray(new InetAddress[]{});
	}


}
