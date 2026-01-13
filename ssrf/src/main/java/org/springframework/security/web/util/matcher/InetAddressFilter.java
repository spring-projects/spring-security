package org.springframework.security.web.util.matcher;

import java.net.InetAddress;
import java.util.List;

/**
 * Component that helps to filter an {@link InetAddress} in or out.
 */
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
		return new DefaultInetAddressVerifierBuilder();
	}


	interface Builder {

		Builder allowList(List<String> addresses);

		Builder denyList(List<String> addresses);

		Builder blockExternal();

		Builder blockInternal();

		Builder addCustomFilter(InetAddressFilter verifier);

		Builder reportOnly();

		InetAddressFilter build();

	}

}
