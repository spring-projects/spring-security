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

import client.dns.SecurityDnsHandler;
// import io.projectreactor.netty.transport.ClientTransportConfig;
// import io.projectreactor.netty.transport.ResolvedAddressSelector;
// import reactor.netty.transport.ResolvedAddressSelector;

import reactor.netty.transport.ClientTransport.ResolvedAddressSelector;
import reactor.netty.transport.ClientTransportConfig;

import java.net.SocketAddress;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

/**
 * A {@link ResolvedAddressSelector} that uses a {@link SecurityDnsHandler} to filter a list of
 * resolved {@link SocketAddress}es for a Reactor Netty client.
 *
 * @see reactor.netty.http.client.HttpClient#resolvedAddressesSelector(ResolvedAddressSelector)
 */
public class NettyHttpClientAddressSelector implements ResolvedAddressSelector<ClientTransportConfig<?>> {

	private final SecurityDnsHandler securityDnsHandler;

	/**
	 * Creates a new instance.
	 * @param securityDnsHandler The handler to apply security rules to the resolved addresses.
	 */
	public NettyHttpClientAddressSelector(SecurityDnsHandler securityDnsHandler) {
		Objects.requireNonNull(securityDnsHandler, "securityDnsHandler must not be null");
		this.securityDnsHandler = securityDnsHandler;
	}

	public List<SocketAddress> select(ClientTransportConfig<?> clientTransportConfig,
			Supplier<List<SocketAddress>> addresses) {

		List<SocketAddress> socketAddresses = addresses.get();
		if (socketAddresses == null || socketAddresses.isEmpty()) {
			return socketAddresses;
		}

		return this.securityDnsHandler.handleSocketAddresses(socketAddresses);
	}

	@Override
	public @Nullable List<? extends SocketAddress> apply(ClientTransportConfig<?> config,
			List<? extends SocketAddress> resolvedAddresses) {
		if (resolvedAddresses == null || resolvedAddresses.isEmpty()) {
			return resolvedAddresses;
		}
		return this.securityDnsHandler.handleSocketAddresses(resolvedAddresses);
	}
}
