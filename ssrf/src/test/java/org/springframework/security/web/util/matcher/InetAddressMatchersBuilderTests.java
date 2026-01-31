package org.springframework.security.web.util.matcher;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link InetAddressMatchers.Builder}.
 */
class InetAddressMatchersBuilderTests {

	private static final InetAddress INTERNAL_IP_1 = initAddress("192.168.1.1");
	private static final InetAddress INTERNAL_IP_2 = initAddress("10.0.0.1");
	private static final InetAddress EXTERNAL_IP_1 = initAddress("8.8.8.8");
	private static final InetAddress EXTERNAL_IP_2 = initAddress("1.1.1.1");
	private static final InetAddress LOCALHOST_IP = initAddress("127.0.0.1");

	private static InetAddress initAddress(String address) {
		try {
			return InetAddress.getByName(address);
		}
		catch (UnknownHostException ex) {
			throw new IllegalArgumentException(ex);
		}
	}


	@Test
	void defaultAllowsAll() {
		InetAddressMatcher filter = InetAddressMatchers.builder().build();

		assertTrue(filter.matches(INTERNAL_IP_1));
		assertTrue(filter.matches(EXTERNAL_IP_1));
	}

	@Test
	void allowList() {
		InetAddressMatcher filter = InetAddressMatchers.builder().allowAddresses(List.of(EXTERNAL_IP_1.getHostAddress())).build();

		assertTrue(filter.matches(EXTERNAL_IP_1));
		assertFalse(filter.matches(EXTERNAL_IP_2));
	}


	@Test
	void denyList() {
		InetAddressMatcher filter = InetAddressMatchers.builder().denyAddresses(List.of(EXTERNAL_IP_1.getHostAddress())).build();

		assertFalse(filter.matches(EXTERNAL_IP_1));
		assertTrue(filter.matches(EXTERNAL_IP_2));
	}

	@Test
	void blockExternal() {
		InetAddressMatcher filter = InetAddressMatchers.matchInternal().build();

		assertTrue(filter.matches(INTERNAL_IP_1));
		assertTrue(filter.matches(LOCALHOST_IP), "Loopback is not external");

		assertFalse(filter.matches(EXTERNAL_IP_1));
		assertFalse(filter.matches(EXTERNAL_IP_2));
	}

	@Test
	void blockInternal() {
		InetAddressMatcher filter = InetAddressMatchers.matchExternal().build();

		assertTrue(filter.matches(EXTERNAL_IP_1));
		assertFalse(filter.matches(INTERNAL_IP_1));
		assertFalse(filter.matches(INTERNAL_IP_2));
		assertFalse(filter.matches(LOCALHOST_IP), "Loopback should be blocked");
	}

	@Test
	void customFilter() {
		InetAddressMatcher filter = InetAddressMatchers.builder().allowList(EXTERNAL_IP_1::equals).build();

		assertTrue(filter.matches(EXTERNAL_IP_1));
		assertFalse(filter.matches(EXTERNAL_IP_2));
	}

	@Test
	void reportOnly() {
		InetAddressMatchers.Builder builder = InetAddressMatchers.builder().allowList(EXTERNAL_IP_1::equals);

		InetAddressMatcher filter = builder.build();
		assertTrue(filter.matches(EXTERNAL_IP_1));
		assertFalse(filter.matches(EXTERNAL_IP_2));

		filter = builder.reportOnly().build();
		assertTrue(filter.matches(EXTERNAL_IP_1));
		assertTrue(filter.matches(EXTERNAL_IP_2));
	}

}
