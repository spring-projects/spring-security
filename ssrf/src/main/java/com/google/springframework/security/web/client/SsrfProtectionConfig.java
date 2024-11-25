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

import com.google.springframework.security.web.client.ListedSsrfProtectionFilter.FilterMode;
import java.util.Arrays;
import java.util.List;


public class SsrfProtectionConfig {


	/**
	 * Helper enum to make configuring with system properties easier
	 */
	enum ProtectionMode {
		ALLOW_LIST,
		DENY_LIST,
		ALLOW_INTERNAL,
		ALLOW_EXTERNAL,
	}

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

	public static SsrfProtectionConfig defaultFilter() {
		String modeProperty = System.getProperty("ssrf.protection.mode");

		SsrfProtectionFilter filter = null;

		if (modeProperty == null) {
			throw new IllegalStateException("ssrf.protection.mode is not set but defaultFilter() requested");
		}
		ProtectionMode mode = ProtectionMode.valueOf(modeProperty.toUpperCase());

		if (mode == ProtectionMode.ALLOW_LIST || mode == ProtectionMode.DENY_LIST) {
			String ipList = System.getProperty("ssrf.protection.iplist");
			if (ipList == null) {
				throw new IllegalStateException(
						"ssrf.protection.iplist is required for ALLOW_LIST or DENY_LIST modes in comma separated CIDR format");
			}
			FilterMode filterMode = (mode == ProtectionMode.ALLOW_LIST ? FilterMode.ALLOW_LIST : FilterMode.BLOCK_LIST);
			filter = new ListedSsrfProtectionFilter(
					Arrays.stream(ipList.strip().split(",")).map(IpOrRange::new).toList(), filterMode);
		}
		if (mode == ProtectionMode.ALLOW_EXTERNAL || mode == ProtectionMode.ALLOW_INTERNAL) {
			BasicSSRFProtectionFilter.FilterMode filterMode = (mode == ProtectionMode.ALLOW_EXTERNAL
					? BasicSSRFProtectionFilter.FilterMode.BLOCK_INTERNAL_ALLOW_EXTERNAL :
					BasicSSRFProtectionFilter.FilterMode.ALLOW_INTERNAL_BLOCK_EXTERNAL);
			filter = new BasicSSRFProtectionFilter(filterMode);
		}

		return new SsrfProtectionConfig(filter);
	}


	public SsrfProtectionFilter getFilter() {
		return filter;
	}
}
