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
package com.google.springframework.security.web.ssrf;

import java.net.InetAddress;
import java.util.List;


public class SsrfProtectionConfig {

	private SsrfProtectionFilter filter;

	public SsrfProtectionConfig(SsrfProtectionFilter filter) {
		this.filter = filter;
	}

	public static SsrfProtectionConfig makeBasicFilter(BasicSSRFProtectionFilter.FilterMode mode) {
		return new SsrfProtectionConfig(new BasicSSRFProtectionFilter(mode));
	}

	public static SsrfProtectionConfig makeListedFilter(List<String> addresses,
			ListedSsrfProtectionFilter.FilterMode mode) {
		return new SsrfProtectionConfig(
				new ListedSsrfProtectionFilter(addresses.stream().map(IpOrRange::new).toList(), mode));
	}

	public static SsrfProtectionConfig defaultFilter(List<String> addresses,
			ListedSsrfProtectionFilter.FilterMode mode) {

		// TODO(vaspori): use/parse system properties
		return new SsrfProtectionConfig(new SsrfProtectionFilter() {
			@Override
			public InetAddress[] filter(InetAddress[] addresses) throws HostBlockedException {
				return addresses;
			}
		});
	}


	public SsrfProtectionFilter getFilter() {
		return filter;
	}
}
