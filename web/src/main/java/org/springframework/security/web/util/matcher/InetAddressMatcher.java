/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.util.matcher;

import java.net.InetAddress;

import org.jspecify.annotations.Nullable;

/**
 * Matches an {@link InetAddress}.
 *
 * @author Rossen Stoyanchev
 * @author Rob Winch
 * @since 7.1
 */
@FunctionalInterface
public interface InetAddressMatcher {

	/**
	 * Whether the given address matches.
	 * @param address the {@link InetAddress} to check (may be {@code null})
	 * @return {@code true} if the address matches, {@code false} otherwise
	 */
	boolean matches(@Nullable InetAddress address);

	/**
	 * Whether the given address string matches.
	 * @param address the IP address string to check (may be {@code null})
	 * @return {@code true} if the address matches, {@code false} otherwise
	 */
	default boolean matches(@Nullable String address) {
		return (address != null) ? matches(InetAddressParser.parseAddress(address)) : false;
	}

}
