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

import io.netty.resolver.AddressResolver;
import io.netty.resolver.AddressResolverGroup;
import io.netty.resolver.DefaultAddressResolverGroup;
import io.netty.util.concurrent.*;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class NettySsrfDnsResolver extends AddressResolverGroup<InetSocketAddress> {

	private static final Log logger = LogFactory.getLog(NettySsrfDnsResolver.class);

	private final List<SsrfProtectionFilter> filters;
	private final boolean reportOnly;
	private final AddressResolverGroup<InetSocketAddress> defaultResolverGroup;

	public NettySsrfDnsResolver(List<SsrfProtectionFilter> filters, boolean reportOnly) {
		this(filters, reportOnly, DefaultAddressResolverGroup.INSTANCE);
	}

	// For testing
	protected NettySsrfDnsResolver(List<SsrfProtectionFilter> filters, boolean reportOnly,
			AddressResolverGroup<InetSocketAddress> defaultResolverGroup) {
		this.filters = filters;
		this.reportOnly = reportOnly;
		this.defaultResolverGroup = defaultResolverGroup;
	}

	@Override
	protected AddressResolver<InetSocketAddress> newResolver(EventExecutor executor) {
		return new AddressResolver<InetSocketAddress>() {
			private final AddressResolver<InetSocketAddress> resolver = defaultResolverGroup.getResolver(executor);

			@Override
			public boolean isSupported(SocketAddress address) {
				if (address instanceof InetSocketAddress) {
					return resolver.isSupported((InetSocketAddress) address);
				}
				return false;
			}

			@Override
			public boolean isResolved(SocketAddress address) {
				return resolver.isResolved(address);
			}

			@Override
			public Future<InetSocketAddress> resolve(SocketAddress address) {
				return resolver.resolve(address);
			}

			@Override
			public Future<InetSocketAddress> resolve(SocketAddress address,
					Promise<InetSocketAddress> promise) {
				return resolver.resolve(address, promise);
			}

			@Override
			public Future<List<InetSocketAddress>> resolveAll(SocketAddress address) {
				if (address instanceof InetSocketAddress inetSocketAddress && inetSocketAddress.isUnresolved()) {
					// This is where we apply our SSRF filtering.
					return resolveAllUnresolved(inetSocketAddress.getHostName(), inetSocketAddress.getPort(), executor.newPromise());
				}
				// If it's already resolved or not an InetSocketAddress, use the default resolver.
				if(address instanceof InetSocketAddress) {
					return resolver.resolveAll((InetSocketAddress) address);
				}
				return executor.newFailedFuture(new IllegalArgumentException("Unsupported address type: " + address.getClass()));
			}

			@Override
			public Future<List<InetSocketAddress>> resolveAll(SocketAddress address, Promise<List<InetSocketAddress>> promise) {
				if (address instanceof InetSocketAddress inetSocketAddress && inetSocketAddress.isUnresolved()) {
					return resolveAllUnresolved(inetSocketAddress.getHostName(), inetSocketAddress.getPort(), promise);
				}
				if(address instanceof InetSocketAddress){
					return resolver.resolveAll((InetSocketAddress) address, promise);
				}
				return promise.setFailure(new IllegalArgumentException("Unsupported address type: " + address.getClass()));

			}


			// Helper method to handle the actual filtering logic (for unresolved addresses)
			private Future<List<InetSocketAddress>> resolveAllUnresolved(String host, int port, Promise<List<InetSocketAddress>> promise) {
				Future<List<InetSocketAddress>> future;
				try{
					future = resolveWithDefaultResolver(host, port);
				} catch(UnknownHostException e){
					return promise.setFailure(e);
				}

				future.addListener((FutureListener<List<InetSocketAddress>>) f -> {
					if (f.isSuccess()) {
						// 1. Get the resolved addresses from the default resolver
						List<InetSocketAddress> resolvedAddresses = f.getNow();

						// 2. Convert to InetAddress array (for your filter interface)
						InetAddress[] inetAddresses = resolvedAddresses.stream()
								.map(InetSocketAddress::getAddress)
								.toArray(InetAddress[]::new);

						// 3. Apply SSRF filters
						try {
							InetAddress[] filteredAddresses = inetAddresses;
							for (SsrfProtectionFilter filter : filters) {
								filteredAddresses = filter.filterAddresses(filteredAddresses);
							}

							// 4. Convert back to InetSocketAddress list
							List<InetSocketAddress> filteredSocketAddresses = Arrays.stream(filteredAddresses)
									.map(addr -> new InetSocketAddress(addr, port)) // Use original port
									.toList();

							// 5. Fulfill the promise with the FILTERED results
							promise.setSuccess(filteredSocketAddresses);

						} catch (HostBlockedException e) {
							logger.error("DNS resolution for '" + host + "' blocked by SSRF filter", e);
							if (reportOnly) {
								// In report-only mode, we still succeed with the *original* addresses
								promise.setSuccess(resolvedAddresses);
							} else {
								// Block the resolution
								promise.setFailure(new UnknownHostException(
										String.format("Access to '%s' was blocked: %s", host, e.getMessage())));
							}
						}
					} else {
						// If the default resolver failed, propagate the failure
						promise.setFailure(f.cause());
					}
				});

				return promise; // Return the promise to the caller
			}


			@Override
			public void close() {
				resolver.close(); // Close the underlying default resolver
			}
		};
	}

	//for testing
	Future<List<InetSocketAddress>> resolveWithDefaultResolver(String host, int port) throws UnknownHostException {
		// Use DefaultAddressResolverGroup to perform the actual DNS lookup
		InetSocketAddress unresolvedAddress = InetSocketAddress.createUnresolved(host, port);

		//This is just to check to see if the default resolver will throw an exception
		resolveAll(host);

		return defaultResolverGroup.getResolver(ImmediateEventExecutor.INSTANCE).resolveAll(unresolvedAddress);
	}

	//for testing
	protected InetAddress[] resolveAll(String host) throws UnknownHostException {
		return InetAddress.getAllByName(host);
	}
}
