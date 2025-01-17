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
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.util.Promise;
import org.eclipse.jetty.util.SocketAddressResolver;

class JettySsrfDnsResolver implements SocketAddressResolver {

	private static final Log logger = LogFactory.getLog(JettySsrfDnsResolver.class);

	protected final List<SsrfProtectionFilter> filters;
	protected boolean reportOnly;

	public JettySsrfDnsResolver(List<SsrfProtectionFilter> filters, boolean reportOnly) {
		this.filters = filters;
		this.reportOnly = reportOnly;
	}

	// Address resolution moved to a helper function for testing purposes
	protected InetAddress[] resolveAll(String host) throws UnknownHostException {
		return InetAddress.getAllByName(host);
	}

	@Override
	public void resolve(String host, int port, Promise<List<InetSocketAddress>> promise) {

		InetAddress[] addresses = null;
		try {
			addresses = resolveAll(host);

			InetAddress[] filteredAddresses = addresses;
			for (SsrfProtectionFilter f : filters) {
				filteredAddresses = f.filterAddresses(filteredAddresses);
			}

			List<InetSocketAddress> socketAddresses = Arrays.stream(filteredAddresses)
					.map(address -> new InetSocketAddress(address, port)).toList();

			promise.succeeded(socketAddresses);
		} catch (HostBlockedException e) {

			logger.error("DNS resolution for '" + host + "' resulted in error", e);

			if (reportOnly) {
				List<InetSocketAddress> socketAddresses = Arrays.stream(addresses)
						.map(address -> new InetSocketAddress(address, port)).toList();
				promise.succeeded(socketAddresses);
			} else {
				promise.failed(new UnknownHostException(
						"Access to " + host + " was blocked because it violates the SSRF protection config"));
			}
		} catch (UnknownHostException e) {
			promise.failed(e);
		}
	}
}
