package com.google.springframework.security.web.client;

import client.dns.InetAddressFilter;
import client.dns.SecurityDnsHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SecurityDnsHandlerTest {

	private InetAddress INTERNAL_IP_1;
	private InetAddress INTERNAL_IP_2;
	private InetAddress EXTERNAL_IP_1;
	private InetAddress EXTERNAL_IP_2;
	private InetAddress LOCALHOST_IP;

	@BeforeEach
	void setUp() throws UnknownHostException {
		INTERNAL_IP_1 = InetAddress.getByName("192.168.1.1"); // site-local
		INTERNAL_IP_2 = InetAddress.getByName("10.0.0.1");     // site-local
		EXTERNAL_IP_1 = InetAddress.getByName("8.8.8.8");   // public
		EXTERNAL_IP_2 = InetAddress.getByName("1.1.1.1");   // public
		LOCALHOST_IP = InetAddress.getByName("127.0.0.1");  // loopback
	}

	// --- Builder Tests ---

	@Test
	void testBuilder_defaults() {
		SecurityDnsHandler handler = SecurityDnsHandler.builder().build();
		assertFalse(handler.getReportMode(), "Default reportOnly mode should be false");

		// Assuming default DefaultInetAddressFilter allows all if no rules are set
		List<InetAddress> addresses = Arrays.asList(INTERNAL_IP_1, EXTERNAL_IP_1);
		List<InetAddress> result = handler.handleAddresses(addresses);
		assertEquals(addresses, result, "With default builder, all addresses should be allowed");
	}

	@Test
	void testBuilder_reportOnlyTrue() {
		SecurityDnsHandler handler = SecurityDnsHandler.builder().reportOnly(true).build();
		assertTrue(handler.getReportMode());
	}

	@Test
	void testBuilder_reportOnlyFalse() {
		SecurityDnsHandler handler = SecurityDnsHandler.builder().reportOnly(false).build();
		assertFalse(handler.getReportMode());
	}

	@Test
	void testBuilder_blockAllExternal_blocksExternalOnly() {
		SecurityDnsHandler handler = SecurityDnsHandler.builder().blockAllExternal(true).build();
		List<InetAddress> candidates = Arrays.asList(INTERNAL_IP_1, EXTERNAL_IP_1, LOCALHOST_IP, EXTERNAL_IP_2);

		List<InetAddress> result = handler.handleAddresses(candidates);

		assertTrue(result.contains(INTERNAL_IP_1));
		assertTrue(result.contains(LOCALHOST_IP)); // Loopback is not external
		assertFalse(result.contains(EXTERNAL_IP_1));
		assertFalse(result.contains(EXTERNAL_IP_2));
		assertEquals(2, result.size(), "Only internal and loopback IPs should pass. Result: " + resultToString(result));
	}

	@Test
	void testBuilder_blockAllInternal_blocksInternalAndLoopback() {
		// Assuming DefaultInetAddressFilter treats loopback as internal for blocking purposes
		SecurityDnsHandler handler = SecurityDnsHandler.builder().blockAllInternal(true).build();
		List<InetAddress> candidates = Arrays.asList(INTERNAL_IP_1, EXTERNAL_IP_1, LOCALHOST_IP, INTERNAL_IP_2);

		List<InetAddress> result = handler.handleAddresses(candidates);

		assertTrue(result.contains(EXTERNAL_IP_1));
		assertFalse(result.contains(INTERNAL_IP_1));
		assertFalse(result.contains(INTERNAL_IP_2));
		assertFalse(result.contains(LOCALHOST_IP)); // Loopback should be blocked
		assertEquals(1, result.size(), "Only external IPs should pass. Result: " + resultToString(result));
	}

	@Test
	void testBuilder_customFilter_blocksSpecificAddress() {
		InetAddressFilter customBlocker = address -> address.equals(EXTERNAL_IP_1);
		SecurityDnsHandler handler = SecurityDnsHandler.builder().customFilter(customBlocker).build();
		List<InetAddress> candidates = Arrays.asList(INTERNAL_IP_1, EXTERNAL_IP_1, EXTERNAL_IP_2);

		List<InetAddress> result = handler.handleAddresses(candidates);

		assertTrue(result.contains(INTERNAL_IP_1));
		assertTrue(result.contains(EXTERNAL_IP_2));
		assertFalse(result.contains(EXTERNAL_IP_1));
		assertEquals(2, result.size());
	}

	@Test
	void handleAddresses_someAddressesBlocked_byFilter() {
		InetAddressFilter blockExternal1Filter = address -> address.equals(EXTERNAL_IP_1);
		SecurityDnsHandler handler = new SecurityDnsHandler(blockExternal1Filter, false);
		List<InetAddress> candidates = Arrays.asList(INTERNAL_IP_1, EXTERNAL_IP_1, EXTERNAL_IP_2);

		List<InetAddress> result = handler.handleAddresses(candidates);

		assertTrue(result.contains(INTERNAL_IP_1));
		assertTrue(result.contains(EXTERNAL_IP_2));
		assertFalse(result.contains(EXTERNAL_IP_1));
		assertEquals(2, result.size());
	}

	@Test
	void handleAddresses_allAddressesBlocked_reportOnlyFalse_returnsEmpty() {
		SecurityDnsHandler handler = SecurityDnsHandler.builder().blockAllInternal(true).reportOnly(false).build();
		List<InetAddress> candidates = Arrays.asList(INTERNAL_IP_1, INTERNAL_IP_2);

		List<InetAddress> result = handler.handleAddresses(candidates);

		assertTrue(result.isEmpty(), "Should return empty list when all are blocked and not in reportOnly mode");
	}

	@Test
	void handleAddresses_allAddressesBlocked_reportOnlyTrue_returnsAllCandidates() {
		SecurityDnsHandler handler = SecurityDnsHandler.builder().blockAllInternal(true).reportOnly(true).build();
		List<InetAddress> candidates = Arrays.asList(INTERNAL_IP_1, EXTERNAL_IP_1);

		List<InetAddress> result = handler.handleAddresses(candidates);

		assertEquals(candidates, result, "Should return all candidates when all are blocked and in reportOnly mode");
	}

	@Test
	void handleAddresses_emptyCandidateList_returnsEmpty() {
		SecurityDnsHandler handler = SecurityDnsHandler.builder().blockAllInternal(true).reportOnly(true).build();
		List<InetAddress> candidates = Collections.emptyList();

		List<InetAddress> result = handler.handleAddresses(candidates);

		assertTrue(result.isEmpty());
	}

	@Test
	void handleInetSocketAddresses_filtersBasedOnAddress_rewritesPort() {
		InetAddressFilter blockExternal1Filter = address -> address.equals(EXTERNAL_IP_1); // This should only filter EXTERNAL_IP_1
		SecurityDnsHandler handler = new SecurityDnsHandler(blockExternal1Filter, false);

		int targetPort = 8080;
		List<InetSocketAddress> candidates = Arrays.asList(
				new InetSocketAddress(INTERNAL_IP_1, 9000),         // original port 9000
				new InetSocketAddress(EXTERNAL_IP_1, targetPort),   // original port 8080 (blocked)
				new InetSocketAddress(EXTERNAL_IP_2, 9001)          // original port 9001
		);

		List<InetSocketAddress> result = handler.handleInetSocketAddresses(candidates, targetPort);

		assertEquals(2, result.size());
		assertTrue(result.stream().anyMatch(sa -> sa.getAddress().equals(INTERNAL_IP_1) && sa.getPort() == targetPort),
				"INTERNAL_IP_1 should be present with targetPort");
		assertTrue(result.stream().anyMatch(sa -> sa.getAddress().equals(EXTERNAL_IP_2) && sa.getPort() == targetPort),
				"EXTERNAL_IP_2 should be present with targetPort");
		assertFalse(result.stream().anyMatch(sa -> sa.getAddress().equals(EXTERNAL_IP_1)),
				"EXTERNAL_IP_1 should be filtered out");
	}

	@Test
	void handleInetSocketAddresses_allAddressesBlocked_reportOnlyFalse_returnsEmpty() {
		InetAddressFilter blockAllFilter = address -> true;
		SecurityDnsHandler handler = new SecurityDnsHandler(blockAllFilter, false);
		int port = 443;
		List<InetSocketAddress> candidates = Arrays.asList(
				new InetSocketAddress(INTERNAL_IP_1, port),
				new InetSocketAddress(EXTERNAL_IP_1, port)
		);
		List<InetSocketAddress> result = handler.handleInetSocketAddresses(candidates, port);

		assertTrue(result.isEmpty());
	}

	@Test
	void handleInetSocketAddresses_allAddressesBlocked_reportOnlyTrue_returnsAllCandidatesWithNewPort() {
		InetAddressFilter blockAllFilter = address -> true;
		SecurityDnsHandler handler = new SecurityDnsHandler(blockAllFilter, true);
		int targetPort = 443;
		List<InetSocketAddress> candidates = Arrays.asList(
				new InetSocketAddress(INTERNAL_IP_1, 8000),
				new InetSocketAddress(EXTERNAL_IP_1, 8001)
		);

		List<InetSocketAddress> result = handler.handleInetSocketAddresses(candidates, targetPort);

		assertEquals(candidates.size(), result.size());
		for (int i = 0; i < candidates.size(); i++) {
			assertEquals(candidates.get(i).getAddress(), result.get(i).getAddress(), "Address should match original candidate");
			assertEquals(targetPort, result.get(i).getPort(), "Port should be rewritten to targetPort");
		}
	}

	// --- Mockito based test for direct InetAddressFilter interaction ---
	@Test
	void handleAddresses_withMockFilter_verifiesFilteringLogic() {
		InetAddressFilter mockFilter = mock(InetAddressFilter.class);
		// Define behavior for mock filter
		when(mockFilter.filterAddress(INTERNAL_IP_1)).thenReturn(false); // Not blocked
		when(mockFilter.filterAddress(EXTERNAL_IP_1)).thenReturn(true);  // Blocked
		when(mockFilter.filterAddress(EXTERNAL_IP_2)).thenReturn(false); // Not blocked

		SecurityDnsHandler handler = new SecurityDnsHandler(mockFilter, false);
		List<InetAddress> candidates = Arrays.asList(INTERNAL_IP_1, EXTERNAL_IP_1, EXTERNAL_IP_2);

		List<InetAddress> result = handler.handleAddresses(candidates);

		assertTrue(result.contains(INTERNAL_IP_1));
		assertFalse(result.contains(EXTERNAL_IP_1));
		assertTrue(result.contains(EXTERNAL_IP_2));
		assertEquals(2, result.size());
	}

	// Helper for better assertion messages
	private String resultToString(List<InetAddress> addresses) {
		return addresses.stream().map(InetAddress::getHostAddress).collect(Collectors.joining(", "));
	}
}
