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
		return builder().allowList(ExternalInetAddressMatcher.getInstance());
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
		return builder().allowList(InternalInetAddressMatcher.getInstance());
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
		 * Adds an allow list matcher that permits only the specified addresses.
		 * @param addresses the list of IP address patterns to allow (cannot be null or
		 * empty)
		 * @return this builder for method chaining
		 * @throws IllegalArgumentException if addresses is null or empty
		 */
		public Builder allowAddresses(List<String> addresses) {
			Assert.notEmpty(addresses, "addresses cannot be empty");
			List<InetAddressMatcher> matchers = addresses.stream()
				.<InetAddressMatcher>map(IpInetAddressMatcher::new)
				.toList();
			this.matchers.add(new AllowListInetAddressMatcher(matchers));
			return this;
		}

		/**
		 * Adds a deny list matcher that blocks the specified addresses.
		 * @param addresses the list of IP address patterns to deny (cannot be null or
		 * empty)
		 * @return this builder for method chaining
		 * @throws IllegalArgumentException if addresses is null or empty
		 */
		public Builder denyAddresses(List<String> addresses) {
			Assert.notEmpty(addresses, "addresses cannot be empty");
			List<InetAddressMatcher> matchers = addresses.stream()
				.<InetAddressMatcher>map(IpInetAddressMatcher::new)
				.toList();
			this.matchers.add(new DenyListInetAddressMatcher(matchers));
			return this;
		}

		/**
		 * Adds custom matchers to the matcher chain.
		 * @param matchers the custom {@link InetAddressMatcher} instances to add (cannot
		 * be null or empty)
		 * @return this builder for method chaining
		 * @throws IllegalArgumentException if matchers is null or empty
		 */
		public Builder allowList(InetAddressMatcher... matchers) {
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
	 * An {@link InetAddressMatcher} that matches addresses against an allow list. Only
	 * addresses that match an entry in the allow list are permitted.
	 *
	 * @author Rossen Stoyanchev
	 * @author Rob Winch
	 */
	static final class AllowListInetAddressMatcher implements InetAddressMatcher {

		private final List<InetAddressMatcher> allowList;

		AllowListInetAddressMatcher(List<InetAddressMatcher> allowList) {
			Assert.notEmpty(allowList, "allowList cannot be null or empty");
			this.allowList = new ArrayList<>(allowList);
		}

		@Override
		public boolean matches(InetAddress address) {
			for (InetAddressMatcher matcher : this.allowList) {
				if (matcher.matches(address)) {
					return true;
				}
			}
			return false;
		}

		@Override
		public String toString() {
			return "AllowListInetAddressMatcher[\"" + this.allowList + "\"]";
		}

	}

	/**
	 * An {@link InetAddressMatcher} that matches addresses against a deny list. Addresses
	 * that match an entry in the deny list are rejected.
	 *
	 * @author Rossen Stoyanchev
	 * @author Rob Winch
	 */
	static final class DenyListInetAddressMatcher implements InetAddressMatcher {

		private final List<InetAddressMatcher> disallowList;

		DenyListInetAddressMatcher(List<InetAddressMatcher> disallowList) {
			Assert.notEmpty(disallowList, "disallowList cannot be null or empty");
			this.disallowList = new ArrayList<>(disallowList);
		}

		@Override
		public boolean matches(InetAddress address) {
			for (InetAddressMatcher matcher : this.disallowList) {
				if (matcher.matches(address)) {
					return false;
				}
			}
			return true;
		}

		@Override
		public String toString() {
			return "DenyListInetAddressMatcher[\"" + this.disallowList + "\"]";
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
		public boolean matches(InetAddress address) {
			if (address.isLoopbackAddress()) {
				return true;
			}

			byte[] rawAddress = address.getAddress();

			int[] iAddr = new int[rawAddress.length];
			for (int i = 0; i < rawAddress.length; i++) {
				iAddr[i] = Byte.toUnsignedInt(rawAddress[i]);
			}

			// Ignoring Multicast addresses
			if (address.getAddress().length == 4) {
				// IPv4 matching
				// 10.x.x.x , 192.168.x.x , 172.16.x.x
				if (iAddr[0] == 10 || (iAddr[0] == 192 && iAddr[1] == 168) || (iAddr[0] == 172 && iAddr[1] == 16)) {
					return true;
				}

			}
			else if (address.getAddress().length == 16) {
				// IPv6, check for Unique Local Addresses
				if (iAddr[0] == 0xfc || iAddr[0] == 0xfd) {
					return true;
				}

				// IPv4/IPv6 translation, 64:ff9b
				if (iAddr[0] == 0x00 && iAddr[1] == 0x64 && iAddr[2] == 0xff && iAddr[3] == 0x9b) {
					int[] ipv4Part = new int[] { iAddr[12], iAddr[13], iAddr[14], iAddr[15] };
					// same check as above plus a check for loopback
					if (ipv4Part[0] == 10 || ipv4Part[0] == 127 || (ipv4Part[0] == 192 && ipv4Part[1] == 168)
							|| (ipv4Part[0] == 172 && ipv4Part[1] == 16)) {
						return true;
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
		public boolean matches(InetAddress address) {
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
		public boolean matches(InetAddress address) {
			boolean result = doMatch(address);
			return (this.reportOnly || result);
		}

		private boolean doMatch(InetAddress address) {
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
