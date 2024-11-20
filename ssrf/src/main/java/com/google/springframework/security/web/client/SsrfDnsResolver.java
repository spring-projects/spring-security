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
import java.util.ArrayList;
import java.util.List;
import org.apache.hc.client5.http.DnsResolver;

class SsrfDnsResolver implements DnsResolver {

	private final SsrfProtectionConfig ssrfProtectionConfig;

	public SsrfDnsResolver(SsrfProtectionConfig ssrfProtectionConfig) {
		this.ssrfProtectionConfig = ssrfProtectionConfig;
	}

	@Override
	public InetAddress[] resolve(final String host) throws UnknownHostException {

		// Internally these results are cached for 30 seconds (by default) to prevent naive DNS rebinding
		// It's important to fetch it from the cache before running checks and to not run resolution again.
		// ( Otherwise this would make us vulnerable to high-frequency switching between valid-invalid addresses )
		InetAddress[] cachedResult = resolveAll(host);

		List<InetAddress> result = new ArrayList<>(cachedResult.length);
		try {
			return ssrfProtectionConfig.getFilter().filter(cachedResult);
		} catch (HostBlockedException e) {
			// TODO(vaspori): log error as well, exception can't be chained
			throw new UnknownHostException(
					"Access to " + host + " was blocked because it violates the SSRF protection config");
		}
	}

	// Address resolution moved to a helper function for testing purposes
	protected InetAddress[] resolveAll(String host) throws UnknownHostException {
		return InetAddress.getAllByName(host);
	}

	@Override
	public String resolveCanonicalHostname(String host) throws UnknownHostException {
		//TODO(vaspori): implement properly
		return host;
	}
}
