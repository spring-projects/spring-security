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


import java.net.InetSocketAddress;
import java.util.List;

import org.eclipse.jetty.util.Promise;
import org.eclipse.jetty.util.SocketAddressResolver;

import org.springframework.security.web.util.matcher.InetAddressFilter;

public class JettyHttpClientFilteringDnsResolver implements SocketAddressResolver {

	private final SocketAddressResolver delegate;

	private final InetAddressFilter filter;


	public JettyHttpClientFilteringDnsResolver(SocketAddressResolver delegate, InetAddressFilter filter) {
		this.delegate = delegate;
		this.filter = filter;
	}

	/**
	 * Creates a new instance using Jetty's default
	 * as the delegate resolver.
	 * @param filter the filter to apply security rules to the resolved addresses.
	 */
	public JettyHttpClientFilteringDnsResolver(InetAddressFilter filter) {
		// Call the primary constructor, using the fully qualified name for the nested static class
		SocketAddressResolver resolver = new Sync();
		this.delegate = resolver;
		this.filter = filter;
	}


	@Override
	public void resolve(String host, int port, Promise<List<InetSocketAddress>> outerPromise) {
		this.delegate.resolve(host, port, new Promise<>() {

			@Override
			public void succeeded(List<InetSocketAddress> candidates) {
				outerPromise.succeeded(candidates.stream()
						.map(InetSocketAddress::getAddress)
						.filter(filter::filter)
						.map(address -> new InetSocketAddress(address, port))
						.toList());
			}

			@Override
			public void failed(Throwable ex) {
				outerPromise.failed(ex);
			}
		});
	}

}
