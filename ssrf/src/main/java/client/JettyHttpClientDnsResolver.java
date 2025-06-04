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

package client;


import java.net.InetSocketAddress;
import java.util.List;

import client.dns.SecurityDnsHandler;
import org.eclipse.jetty.util.Promise;
import org.eclipse.jetty.util.SocketAddressResolver;

public class JettyHttpClientDnsResolver implements SocketAddressResolver {

	private final SocketAddressResolver delegate;

	private final SecurityDnsHandler securityDnsHandler;


	public JettyHttpClientDnsResolver(SocketAddressResolver delegate, SecurityDnsHandler securityDnsHandler) {
		this.delegate = delegate;
		this.securityDnsHandler = securityDnsHandler;
	}


	@Override
	public void resolve(String host, int port, Promise<List<InetSocketAddress>> promise) {
		this.delegate.resolve(host, port, new Promise<>() {

			@Override
			public void succeeded(List<InetSocketAddress> candidates) {
				Promise.super.succeeded(securityDnsHandler.handleInetSocketAddresses(candidates, port));
			}

			@Override
			public void failed(Throwable ex) {
				Promise.super.failed(ex);
			}
		});
	}

}
