package com.google.springframework.security.web.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class BasicSSRFProtectionFilterTest {

	@Test
	void testAllowInternalBlockExternal_internalAllowed() throws UnknownHostException, HostBlockedException {
		BasicSSRFProtectionFilter filter = new BasicSSRFProtectionFilter(
				BasicSSRFProtectionFilter.FilterMode.ALLOW_INTERNAL_BLOCK_EXTERNAL);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.1"),
				InetAddress.getByName("10.0.0.1")};
		InetAddress[] filtered = filter.filter(addresses);
		assertEquals(2, filtered.length);
		assertTrue(Arrays.asList(filtered).containsAll(List.of(addresses)));
	}

	@Test
	void testAllowInternalBlockExternal_externalBlocked() throws UnknownHostException, HostBlockedException {
		BasicSSRFProtectionFilter filter = new BasicSSRFProtectionFilter(
				BasicSSRFProtectionFilter.FilterMode.ALLOW_INTERNAL_BLOCK_EXTERNAL);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.1"),
				InetAddress.getByName("8.8.8.8")};
		InetAddress[] filtered = filter.filter(addresses);
		assertEquals(1, filtered.length);
		assertEquals(InetAddress.getByName("192.168.1.1"), filtered[0]);
	}

	@Test
	void testAllowInternalBlockExternal_allBlocked() throws UnknownHostException {
		BasicSSRFProtectionFilter filter = new BasicSSRFProtectionFilter(
				BasicSSRFProtectionFilter.FilterMode.ALLOW_INTERNAL_BLOCK_EXTERNAL);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("8.8.8.8"), InetAddress.getByName("1.1.1.1")};
		assertThrows(HostBlockedException.class, () -> filter.filter(addresses));
	}

	@Test
	void testBlockInternalAllowExternal_internalBlocked() throws UnknownHostException, HostBlockedException {
		BasicSSRFProtectionFilter filter = new BasicSSRFProtectionFilter(
				BasicSSRFProtectionFilter.FilterMode.BLOCK_INTERNAL_ALLOW_EXTERNAL);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.1"),
				InetAddress.getByName("8.8.8.8")};
		InetAddress[] filtered = filter.filter(addresses);
		assertEquals(1, filtered.length);
		assertEquals(InetAddress.getByName("8.8.8.8"), filtered[0]);
	}

	@Test
	void testBlockInternalAllowExternal_externalAllowed() throws UnknownHostException, HostBlockedException {
		BasicSSRFProtectionFilter filter = new BasicSSRFProtectionFilter(
				BasicSSRFProtectionFilter.FilterMode.BLOCK_INTERNAL_ALLOW_EXTERNAL);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("8.8.8.8"), InetAddress.getByName("1.1.1.1")};
		InetAddress[] filtered = filter.filter(addresses);
		assertEquals(2, filtered.length);
		assertTrue(Arrays.asList(filtered).containsAll(List.of(addresses)));
	}

	@Test
	void testBlockInternalAllowExternal_allBlocked() throws UnknownHostException {
		BasicSSRFProtectionFilter filter = new BasicSSRFProtectionFilter(
				BasicSSRFProtectionFilter.FilterMode.BLOCK_INTERNAL_ALLOW_EXTERNAL);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.1"),
				InetAddress.getByName("10.0.0.1")};
		assertThrows(HostBlockedException.class, () -> filter.filter(addresses));
	}

	@Test
	void testHostBlockedExceptionMessage() throws UnknownHostException {
		BasicSSRFProtectionFilter filter = new BasicSSRFProtectionFilter(
				BasicSSRFProtectionFilter.FilterMode.BLOCK_INTERNAL_ALLOW_EXTERNAL);
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("192.168.1.1"),
				InetAddress.getByName("10.0.0.1")};
		HostBlockedException exception = assertThrows(HostBlockedException.class, () -> filter.filter(addresses));
		assertTrue(exception.getMessage().contains("192.168.1.1"));
		assertTrue(exception.getMessage().contains("10.0.0.1"));
		assertTrue(exception.getMessage().contains("BLOCK_INTERNAL_ALLOW_EXTERNAL"));
	}
}
