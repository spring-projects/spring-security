package com.google.springframework.security.web.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class ListedSsrfProtectionFilterTest {

	@Test
	void testBlockListWithBlockedAddress() throws UnknownHostException, HostBlockedException {
		List<IpOrRange> blockList = List.of(new IpOrRange("192.168.1.1"), new IpOrRange("10.0.0.0/24"));
		ListedSsrfProtectionFilter filter = new ListedSsrfProtectionFilter(blockList,
				ListedSsrfProtectionFilter.FilterMode.BLOCK_LIST);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.1"),
				InetAddress.getByName("8.8.8.8")};
		InetAddress[] filtered = filter.filterAddresses(addresses);
		assertEquals(1, filtered.length);
		assertEquals(InetAddress.getByName("8.8.8.8"), filtered[0]);
	}

	@Test
	void testBlockListWithAllowedAddress() throws UnknownHostException, HostBlockedException {
		List<IpOrRange> blockList = List.of(new IpOrRange("192.168.1.1"), new IpOrRange("10.0.0.0/24"));
		ListedSsrfProtectionFilter filter = new ListedSsrfProtectionFilter(blockList,
				ListedSsrfProtectionFilter.FilterMode.BLOCK_LIST);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.2"),
				InetAddress.getByName("8.8.8.8")};
		InetAddress[] filtered = filter.filterAddresses(addresses);
		assertEquals(2, filtered.length);
		assertTrue(Arrays.asList(filtered).containsAll(List.of(addresses)));
	}

	@Test
	void testBlockListWithAllBlocked() throws UnknownHostException {
		List<IpOrRange> blockList = List.of(new IpOrRange("192.168.1.0/24"), new IpOrRange("8.8.8.8"));
		ListedSsrfProtectionFilter filter = new ListedSsrfProtectionFilter(blockList,
				ListedSsrfProtectionFilter.FilterMode.BLOCK_LIST);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.1"),
				InetAddress.getByName("8.8.8.8")};
		assertThrows(HostBlockedException.class, () -> filter.filterAddresses(addresses));
	}

	@Test
	void testAllowListWithAllowedAddress() throws UnknownHostException, HostBlockedException {
		List<IpOrRange> allowList = List.of(new IpOrRange("192.168.1.1"), new IpOrRange("10.0.0.0/24"));
		ListedSsrfProtectionFilter filter = new ListedSsrfProtectionFilter(allowList,
				ListedSsrfProtectionFilter.FilterMode.ALLOW_LIST);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.1"),
				InetAddress.getByName("8.8.8.8")};
		InetAddress[] filtered = filter.filterAddresses(addresses);
		assertEquals(1, filtered.length);
		assertEquals(InetAddress.getByName("192.168.1.1"), filtered[0]);
	}

	@Test
	void testAllowListWithBlockedAddress() throws UnknownHostException, HostBlockedException {
		List<IpOrRange> allowList = List.of(new IpOrRange("192.168.1.1"), new IpOrRange("10.0.0.0/24"));
		ListedSsrfProtectionFilter filter = new ListedSsrfProtectionFilter(allowList,
				ListedSsrfProtectionFilter.FilterMode.ALLOW_LIST);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.200"),
				InetAddress.getByName("8.8.8.8")};
		HostBlockedException ex = assertThrows(HostBlockedException.class, () -> filter.filterAddresses(addresses),
				"This should throw an exception");
		assertTrue(ex.getMessage().contains("blocked due to violating ALLOW_LIST"));

	}

	@Test
	void testAllowListWithAllBlocked() throws UnknownHostException {
		List<IpOrRange> allowList = List.of(new IpOrRange("172.16.0.0/16"));
		ListedSsrfProtectionFilter filter = new ListedSsrfProtectionFilter(allowList,
				ListedSsrfProtectionFilter.FilterMode.ALLOW_LIST);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.1"),
				InetAddress.getByName("8.8.8.8")};
		assertThrows(HostBlockedException.class, () -> filter.filterAddresses(addresses));
	}

	@Test
	void testHostBlockedExceptionMessage() throws UnknownHostException {
		List<IpOrRange> blockList = List.of(new IpOrRange("192.168.1.0/24"));
		ListedSsrfProtectionFilter filter = new ListedSsrfProtectionFilter(blockList,
				ListedSsrfProtectionFilter.FilterMode.BLOCK_LIST);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.1")};
		HostBlockedException exception = assertThrows(HostBlockedException.class,
				() -> filter.filterAddresses(addresses));
		assertTrue(exception.getMessage().contains("192.168.1.1"));
		assertTrue(exception.getMessage().contains("BLOCK_LIST"));
	}

}
