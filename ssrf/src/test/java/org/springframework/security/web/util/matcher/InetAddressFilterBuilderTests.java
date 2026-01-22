package org.springframework.security.web.util.matcher;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link InetAddressFilter.Builder}.
 */
public class InetAddressFilterBuilderTests {

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
		InetAddressFilter filter = InetAddressFilter.builder().build();

		assertTrue(filter.filter(INTERNAL_IP_1));
		assertTrue(filter.filter(EXTERNAL_IP_1));
	}

	@Test
	void allowList() {
		InetAddressFilter filter = InetAddressFilter.builder().allowList(List.of(EXTERNAL_IP_1.getHostAddress())).build();

		assertTrue(filter.filter(EXTERNAL_IP_1));
		assertFalse(filter.filter(EXTERNAL_IP_2));
	}


	@Test
	void denyList() {
		InetAddressFilter filter = InetAddressFilter.builder().denyList(List.of(EXTERNAL_IP_1.getHostAddress())).build();

		assertFalse(filter.filter(EXTERNAL_IP_1));
		assertTrue(filter.filter(EXTERNAL_IP_2));
	}

	@Test
	void blockExternal() {
		InetAddressFilter filter = InetAddressFilter.builder().blockExternal().build();

		assertTrue(filter.filter(INTERNAL_IP_1));
		assertTrue(filter.filter(LOCALHOST_IP), "Loopback is not external");

		assertFalse(filter.filter(EXTERNAL_IP_1));
		assertFalse(filter.filter(EXTERNAL_IP_2));
	}

	@Test
	void blockInternal() {
		InetAddressFilter filter = InetAddressFilter.builder().blockInternal().build();

		assertTrue(filter.filter(EXTERNAL_IP_1));
		assertFalse(filter.filter(INTERNAL_IP_1));
		assertFalse(filter.filter(INTERNAL_IP_2));
		assertFalse(filter.filter(LOCALHOST_IP), "Loopback should be blocked");
	}

	@Test
	void blockInternalExternalAreMutuallyExclusive() {
		assertThrows(IllegalArgumentException.class,
				() -> InetAddressFilter.builder().blockExternal().blockInternal(),
				"blockExternal and blockInternal are mutually exclusive options");
	}

	@Test
	void customFilter() {
		InetAddressFilter filter = InetAddressFilter.builder().customFilter(EXTERNAL_IP_1::equals).build();

		assertTrue(filter.filter(EXTERNAL_IP_1));
		assertFalse(filter.filter(EXTERNAL_IP_2));
	}

	@Test
	void reportOnly() {
		InetAddressFilter.Builder builder = InetAddressFilter.builder().customFilter(EXTERNAL_IP_1::equals);

		InetAddressFilter filter = builder.build();
		assertTrue(filter.filter(EXTERNAL_IP_1));
		assertFalse(filter.filter(EXTERNAL_IP_2));

		filter = builder.reportOnly().build();
		assertTrue(filter.filter(EXTERNAL_IP_1));
		assertTrue(filter.filter(EXTERNAL_IP_2));
	}

}
