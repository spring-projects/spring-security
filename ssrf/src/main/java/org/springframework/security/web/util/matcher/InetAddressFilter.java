package org.springframework.security.web.util.matcher;

import java.net.InetAddress;
import java.util.List;

/**
 * Component that helps to filter an {@link InetAddress} in or out.
 */
@FunctionalInterface
public interface InetAddressFilter {

	/**
	 * Whether the given address should be filtered in or out.
	 * @return {@code true} if the address is allowed for use, and {@code false}
	 * if it is restricted and should not be used.
	 */
	boolean filter(InetAddress address);


	/**
	 * Return a builder to for a composite {@link InetAddressFilter} that
	 * delegates to any number of other filters.
	 */
	static Builder builder() {
		return new DefaultInetAddressBuilder();
	}


	/**
	 * Builder to create a composite {@link InetAddressFilter}.
	 */
	interface Builder {

		/**
		 * Add filter that matches addresses if found in an "allow" list.
		 * @param addresses the allow list of addresses
		 * @return the same builder instance
		 */
		Builder allowList(List<String> addresses);

		/**
		 * Add filter that matches addresses if not found in a "deny" list.
		 * @param addresses the deny list of addresses
		 * @return the same builder instance
		 */
		Builder denyList(List<String> addresses);

		/**
		 * Add filter that blocks all external addresses.
		 * @return the same builder instance
		 */
		Builder blockExternal();

		/**
		 * Add filter that blocks all internal addresses.
		 * @return the same builder instance
		 */
		Builder blockInternal();

		/**
		 * Add filter with custom logic to match addresses.
		 * @param filter the filter to add
		 * @return the same builder instance
		 */
		Builder customFilter(InetAddressFilter filter);

		/**
		 * Enable a "report-only" mode that only logs debug messages, and always matches.
		 * @return the same builder instance
		 */
		Builder reportOnly();

		/**
		 * Return the created composite {@link InetAddressFilter} instance.
		 */
		InetAddressFilter build();
	}

}
