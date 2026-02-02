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
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.util.Assert;

/**
 * Factory for creating {@link InetAddressMatcher} instances with various matching
 * strategies for IP addresses.
 *
 * @author Rob Winch
 * @since 7.1
 */
public final class InetAddressMatchers {

	private InetAddressMatchers() {
	}

	/**
	 * Creates a new builder for configuring an {@link InetAddressMatcher}.
	 * @return a new {@link Builder} instance
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates a new builder configured to match external (non-private) IP addresses.
	 * @return a {@link Builder} configured to match external addresses
	 */
	public static Builder matchExternal() {
		return builder().matchAll(ExternalInetAddressMatcher.getInstance());
	}

	/**
	 * Creates a new builder configured to match internal (private) IP addresses.
	 * <p>
	 * Internal addresses include loopback addresses (127.0.0.0/8 for IPv4, ::1 for IPv6),
	 * private IPv4 address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and IPv6
	 * Unique Local Addresses (fc00::/7).
	 * @return a {@link Builder} configured to match internal addresses
	 */
	public static Builder matchInternal() {
		return builder().matchAll(InternalInetAddressMatcher.getInstance());
	}

	/**
	 * A builder for constructing {@link InetAddressMatcher} instances with various
	 * matching rules.
	 *
	 * @author Kian Jamali
	 * @author Gábor Vaspöri
	 * @author Rossen Stoyanchev
	 * @author Rob Winch
	 */
	public static final class Builder {

		private final List<InetAddressMatcher> matchers = new ArrayList<>();

		private boolean reportOnly;

		/**
		 * Adds an include list matcher that permits only the specified addresses.
		 * @param addresses the list of IP address patterns to include (cannot be null or
		 * empty)
		 * @return this builder for method chaining
		 * @throws IllegalArgumentException if addresses is null or empty
		 */
		public Builder includeAddresses(List<String> addresses) {
			Assert.notEmpty(addresses, "addresses cannot be empty");
			List<InetAddressMatcher> matchers = addresses.stream()
				.<InetAddressMatcher>map(IpInetAddressMatcher::new)
				.toList();
			this.matchers.add(new IncludeListInetAddressMatcher(matchers));
			return this;
		}

		/**
		 * Adds an exclude list matcher that blocks the specified addresses.
		 * @param addresses the list of IP address patterns to exclude (cannot be null or
		 * empty)
		 * @return this builder for method chaining
		 * @throws IllegalArgumentException if addresses is null or empty
		 */
		public Builder excludeAddresses(List<String> addresses) {
			Assert.notEmpty(addresses, "addresses cannot be empty");
			List<InetAddressMatcher> matchers = addresses.stream()
				.<InetAddressMatcher>map(IpInetAddressMatcher::new)
				.toList();
			this.matchers.add(new ExcludeListInetAddressMatcher(matchers));
			return this;
		}

		/**
		 * Adds custom matchers to the matcher chain. All matchers must match for an
		 * address to be permitted.
		 * @param matchers the custom {@link InetAddressMatcher} instances to add (cannot
		 * be null or empty)
		 * @return this builder for method chaining
		 * @throws IllegalArgumentException if matchers is null or empty
		 */
		public Builder matchAll(InetAddressMatcher... matchers) {
			Assert.notEmpty(matchers, "matchers cannot be empty");
			for (InetAddressMatcher matcher : matchers) {
				this.matchers.add(matcher);
			}
			return this;
		}

		/**
		 * Configures the matcher to operate in report-only mode. In this mode, matching
		 * logic is evaluated and logged, but all addresses are allowed regardless of
		 * match results.
		 * @return this builder for method chaining
		 */
		public Builder reportOnly() {
			this.reportOnly = true;
			return this;
		}

		/**
		 * Builds the configured {@link InetAddressMatcher}.
		 * @return the constructed {@link InetAddressMatcher}
		 */
		public InetAddressMatcher build() {
			return new CompositeInetAddressMatcher(this.matchers, this.reportOnly);
		}

	}

	/**
	 * An {@link InetAddressMatcher} that matches addresses against an include list. Only
	 * addresses that match an entry in the include list are permitted.
	 *
	 * @author Rossen Stoyanchev
	 * @author Rob Winch
	 */
	static final class IncludeListInetAddressMatcher implements InetAddressMatcher {

		private final List<InetAddressMatcher> includeList;

		IncludeListInetAddressMatcher(List<InetAddressMatcher> includeList) {
			Assert.notEmpty(includeList, "includeList cannot be null or empty");
			this.includeList = new ArrayList<>(includeList);
		}

		@Override
		public boolean matches(@Nullable InetAddress address) {
			for (InetAddressMatcher matcher : this.includeList) {
				if (matcher.matches(address)) {
					return true;
				}
			}
			return false;
		}

		@Override
		public String toString() {
			return "IncludeListInetAddressMatcher[\"" + this.includeList + "\"]";
		}

	}

	/**
	 * An {@link InetAddressMatcher} that matches addresses against an exclude list.
	 * Addresses that match an entry in the exclude list are rejected.
	 *
	 * @author Rossen Stoyanchev
	 * @author Rob Winch
	 */
	static final class ExcludeListInetAddressMatcher implements InetAddressMatcher {

		private final List<InetAddressMatcher> excludeList;

		ExcludeListInetAddressMatcher(List<InetAddressMatcher> excludeList) {
			Assert.notEmpty(excludeList, "excludeList cannot be null or empty");
			this.excludeList = new ArrayList<>(excludeList);
		}

		@Override
		public boolean matches(@Nullable InetAddress address) {
			for (InetAddressMatcher matcher : this.excludeList) {
				if (matcher.matches(address)) {
					return false;
				}
			}
			return true;
		}

		@Override
		public String toString() {
			return "ExcludeListInetAddressMatcher[\"" + this.excludeList + "\"]";
		}

	}

	/**
	 * An {@link InetAddressMatcher} that matches internal (private) addresses.
	 * <p>
	 * Internal addresses include loopback addresses (127.0.0.0/8 for IPv4, ::1 for IPv6),
	 * private IPv4 address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and IPv6
	 * Unique Local Addresses (fc00::/7).
	 *
	 * @author Gábor Vaspöri
	 * @author Kian Jamali
	 * @author Rossen Stoyanchev
	 * @author Rob Winch
	 */
	static final class InternalInetAddressMatcher implements InetAddressMatcher {

		private static final InternalInetAddressMatcher INSTANCE = new InternalInetAddressMatcher();

		static InternalInetAddressMatcher getInstance() {
			return INSTANCE;
		}

		private InternalInetAddressMatcher() {
		}

		@Override
		public boolean matches(@Nullable InetAddress address) {
			if (address == null) {
				return false;
			}
			if (address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress()) {
				return true;
			}

			byte[] rawAddress = address.getAddress();

			if (rawAddress.length == 16) {
				// Convert signed bytes to unsigned ints for easier matching logic
				int[] iAddr = new int[rawAddress.length];
				for (int i = 0; i < rawAddress.length; i++) {
					iAddr[i] = Byte.toUnsignedInt(rawAddress[i]);
				}

				/*
				 * IPv6, check for Unique Local Addresses. We cannot rely on
				 * Inet6Address.isSiteLocalAddress() here because the JVM implementation
				 * dictates that fec0::/10 is the only site-local IPv6 address space,
				 * based on the outdated RFC 2373. That RFC was deprecated by the IETF in
				 * 2004 in favor of fc00::/7 (RFC 4193). To keep our private network
				 * checking accurate to modern subnets, we maintain manual parsing.
				 */
				if (iAddr[0] == 0xfc || iAddr[0] == 0xfd) {
					return true;
				}

				// IPv4/IPv6 translation, 64:ff9b
				if (iAddr[0] == 0x00 && iAddr[1] == 0x64 && iAddr[2] == 0xff && iAddr[3] == 0x9b) {
					try {
						InetAddress ipv4Part = InetAddress.getByAddress(
								new byte[] { rawAddress[12], rawAddress[13], rawAddress[14], rawAddress[15] });

						if (ipv4Part.isLoopbackAddress() || ipv4Part.isLinkLocalAddress()
								|| ipv4Part.isSiteLocalAddress()) {
							return true;
						}
					}
					catch (java.net.UnknownHostException ex) {
						// Should not happen for 4-byte array
					}
				}
			}

			return false;
		}

		@Override
		public String toString() {
			return "InternalInetAddressMatcher";
		}

	}

	/**
	 * An {@link InetAddressMatcher} that matches external (public) addresses.
	 * <p>
	 * External addresses are any addresses that are not internal (private) addresses.
	 * This matcher delegates to {@link InternalInetAddressMatcher} and negates the
	 * result.
	 *
	 * @author Gábor Vaspöri
	 * @author Kian Jamali
	 * @author Rossen Stoyanchev
	 * @author Rob Winch
	 */
	static final class ExternalInetAddressMatcher implements InetAddressMatcher {

		private static final ExternalInetAddressMatcher INSTANCE = new ExternalInetAddressMatcher();

		static ExternalInetAddressMatcher getInstance() {
			return INSTANCE;
		}

		private final InternalInetAddressMatcher internalMatcher = InternalInetAddressMatcher.getInstance();

		private ExternalInetAddressMatcher() {
		}

		@Override
		public boolean matches(@Nullable InetAddress address) {
			return !this.internalMatcher.matches(address);
		}

		@Override
		public String toString() {
			return "ExternalInetAddressMatcher";
		}

	}

	/**
	 * A composite {@link InetAddressMatcher} that chains multiple matchers together. All
	 * matchers must match for an address to be allowed. If report-only mode is enabled,
	 * matching results are logged but all addresses are permitted.
	 *
	 * @author Gábor Vaspöri
	 * @author Kian Jamali
	 * @author Rossen Stoyanchev
	 * @author Rob Winch
	 */
	static final class CompositeInetAddressMatcher implements InetAddressMatcher {

		private static final Log logger = LogFactory.getLog(InetAddressMatcher.class);

		private final List<InetAddressMatcher> matchers;

		private final boolean reportOnly;

		CompositeInetAddressMatcher(List<InetAddressMatcher> matchers, boolean reportOnly) {
			this.matchers = new ArrayList<>(matchers);
			this.reportOnly = reportOnly;
		}

		@Override
		public boolean matches(@Nullable InetAddress address) {
			boolean result = doMatch(address);
			return (this.reportOnly || result);
		}

		private boolean doMatch(@Nullable InetAddress address) {
			for (InetAddressMatcher matcher : this.matchers) {
				if (!matcher.matches(address)) {
					if (logger.isDebugEnabled()) {
						logger.debug("InetAddress " + address + " blocked by " + matcher);
					}
					return false;
				}
			}
			return true;
		}

	}

}
