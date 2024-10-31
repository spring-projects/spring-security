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
import java.net.UnknownHostException;

import org.apache.hc.client5.http.DnsResolver;

class CustomDnsResolver implements DnsResolver {

	private final SsrfProtectionConfig ssrfProtectionConfig;

	public CustomDnsResolver(SsrfProtectionConfig ssrfProtectionConfig) {
		this.ssrfProtectionConfig = ssrfProtectionConfig;
	}

	@Override
	public InetAddress[] resolve(final String host) throws UnknownHostException {
		if (this.ssrfProtectionConfig.getBannedIps().contains(host)) {
			throw new UnknownHostException("Blocked access to IP: " + host);
		}

		if (!this.ssrfProtectionConfig.isAllowInternalIp() && isInternalIp(host)) {
			throw new UnknownHostException("Blocked access to internal IP: " + host);
		}

		if (!this.ssrfProtectionConfig.isAllowExternalIp() && !isInternalIp(host)) {
			throw new UnknownHostException("Blocked access to external IP: " + host);
		}

		// Default behavior: allow if not banned and no allow rules are set
		return InetAddress.getAllByName(host);
	}

	private boolean isInternalIp(String host) {
		// Implement your logic to determine if an IP is internal
		// This is a simplified example, you might need more robust checks
		return host.startsWith("10.") || host.startsWith("192.168.") || host.startsWith(
				"172.16.") || host.startsWith("fd00:");
	}

	@Override
	public String resolveCanonicalHostname(String host) throws UnknownHostException {
		return host;
	}
}
