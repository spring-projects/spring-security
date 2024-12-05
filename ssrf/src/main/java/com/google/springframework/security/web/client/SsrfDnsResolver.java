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
import java.util.Arrays;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hc.client5.http.DnsResolver;

class SsrfDnsResolver implements DnsResolver {


	private static final Log logger = LogFactory.getLog(SsrfDnsResolver.class);


	protected final List<SsrfProtectionFilter> filters;

	public SsrfDnsResolver(List<SsrfProtectionFilter> filters) {
		this.filters = filters;
	}

	@Override
	public InetAddress[] resolve(final String host) throws UnknownHostException {

		// Internally these results are cached for 30 seconds (by default) to prevent naive DNS rebinding
		// It's important to fetch it from the cache before running checks and to not run resolution again.
		// ( Otherwise this would make us vulnerable to high-frequency switching between valid-invalid addresses )
		InetAddress[] cachedResult = resolveAll(host);
		InetAddress[] results = Arrays.copyOf(cachedResult, cachedResult.length);

		try {
			for (SsrfProtectionFilter f : filters) {
				// each filter can restrict the list of addresses resolved to a given host
				results = f.filterAddresses(results);
			}
			return results;
		} catch (HostBlockedException e) {
			// log error as well, exception can't be chained
			logger.error("DNS resolution for '" + host + "' resulted in error", e);
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
		if (host == null) {
			return null;
		}
		final InetAddress in = InetAddress.getByName(host);
		final String canonicalServer = in.getCanonicalHostName();
		if (in.getHostAddress().contentEquals(canonicalServer)) {
			return host;
		}
		return canonicalServer;
	}
}
