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
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.jspecify.annotations.Nullable;
import reactor.netty.transport.ClientTransport.ResolvedAddressSelector;
import reactor.netty.transport.ClientTransportConfig;

import org.springframework.security.web.util.matcher.InetAddressMatcher;
import org.springframework.security.web.util.matcher.InetAddressMatcher;

/**
 * A {@link ResolvedAddressSelector} that uses a {@link InetAddressMatcher} to filter a list of
 * resolved {@link SocketAddress}es for a Reactor Netty client.
 *
 * @see reactor.netty.http.client.HttpClient#resolvedAddressesSelector(ResolvedAddressSelector)
 */
public class NettyHttpClientFilteringAddressSelector implements ResolvedAddressSelector<ClientTransportConfig<?>> {

	private final InetAddressMatcher filter;

	/**
	 * Creates a new instance.
	 * @param filter The filter to apply security rules to the resolved addresses.
	 */
	public NettyHttpClientFilteringAddressSelector(InetAddressMatcher filter) {
		Objects.requireNonNull(filter, "InetAddressMatcher must not be null");
		this.filter = filter;
	}

	public List<SocketAddress> select(ClientTransportConfig<?> clientTransportConfig,
			Supplier<List<SocketAddress>> addresses) {

		return filterInternal(addresses.get());
	}

	@Override
	public @Nullable List<? extends SocketAddress> apply(ClientTransportConfig<?> config,
			List<? extends SocketAddress> resolvedAddresses) {

		return filterInternal(resolvedAddresses);
	}

	private List<SocketAddress> filterInternal(List<? extends SocketAddress> socketAddresses) {

		if (socketAddresses == null || socketAddresses.isEmpty()) {
			return (List<SocketAddress>) socketAddresses;
		}

		List<InetAddress> filteredIn = socketAddresses.stream()
				.filter(InetSocketAddress.class::isInstance)
				.map(InetSocketAddress.class::cast)
				.map(InetSocketAddress::getAddress)
				.filter(this.filter::matches)
				.toList();

		return socketAddresses.stream()
				.filter(sa -> !(sa instanceof InetSocketAddress isa) || filteredIn.contains(isa.getAddress()))
				.collect(Collectors.toList());
	}

}
