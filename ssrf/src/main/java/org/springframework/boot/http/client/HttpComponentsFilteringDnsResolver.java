/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.boot.http.client;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;

import org.springframework.security.web.util.matcher.InetAddressMatcher;

public class HttpComponentsFilteringDnsResolver implements DnsResolver {

	private final DnsResolver delegate;

	private final InetAddressMatcher filter;


	public HttpComponentsFilteringDnsResolver(InetAddressMatcher filter) {
		this(SystemDefaultDnsResolver.INSTANCE, filter);
	}

	public HttpComponentsFilteringDnsResolver(DnsResolver delegate, InetAddressMatcher filter) {
		this.delegate = delegate;
		this.filter = filter;
	}


	@Override
	public InetAddress[] resolve(String host) throws UnknownHostException {
		return Arrays.stream(this.delegate.resolve(host))
				.filter(this.filter::matches).toArray(InetAddress[]::new);
	}

	@Override
	public String resolveCanonicalHostname(String host) throws UnknownHostException {
		return this.delegate.resolveCanonicalHostname(host);
	}
}
