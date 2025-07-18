package com.google.springframework.security.web.client;

import client.dns.SecurityDnsHandler;
import client.JettyHttpClientDnsResolver;
import org.eclipse.jetty.util.Promise;
import org.eclipse.jetty.util.SocketAddressResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JettyHttpClientDnsResolverTest {

	@Mock
	private SocketAddressResolver mockDelegateResolver;

	@Mock
	private SecurityDnsHandler mockSecurityDnsHandler;

	@Mock
	private Promise<List<InetSocketAddress>> mockResultPromise;

	@Captor
	private ArgumentCaptor<Promise<List<InetSocketAddress>>> delegatePromiseCaptor;

	@Captor
	private ArgumentCaptor<List<InetSocketAddress>> resultListCaptor;

	private JettyHttpClientDnsResolver jettyHttpClientDnsResolver;

	private final String HOST = "example.com";
	private final int PORT = 80;

	private List<InetSocketAddress> initialAddresses;
	private List<InetSocketAddress> filteredAddresses;

	@BeforeEach
	void setUp() throws UnknownHostException {
		// Initialize the class under test with mocked dependencies
		jettyHttpClientDnsResolver = new JettyHttpClientDnsResolver(mockDelegateResolver, mockSecurityDnsHandler);

		// Prepare sample data
		InetSocketAddress address1 = new InetSocketAddress(InetAddress.getByAddress(HOST, new byte[]{1, 2, 3, 4}), PORT);
		InetSocketAddress address2 = new InetSocketAddress(InetAddress.getByAddress(HOST, new byte[]{1, 2, 3, 5}), PORT);
		InetSocketAddress address3 = new InetSocketAddress(InetAddress.getByAddress(HOST, new byte[]{1, 2, 3, 6}), PORT);

		initialAddresses = new ArrayList<>(Arrays.asList(address1, address2, address3));
		// SecurityDnsHandler will remove address2
		filteredAddresses = new ArrayList<>(Arrays.asList(address1, address3));
	}

	@Test
	void resolve_whenDelegateSucceeds_shouldApplySecurityHandlerAndReturnFilteredAddresses() {
		// 1. Configure mock SecurityDnsHandler
		// When handleInetSocketAddresses is called with the initial list, return the filtered list
		when(mockSecurityDnsHandler.handleInetSocketAddresses(initialAddresses, PORT))
				.thenReturn(filteredAddresses);

		// 2. Call the method under test
		jettyHttpClientDnsResolver.resolve(HOST, PORT, mockResultPromise);

		// 3. Verify that the delegate resolver's resolve method was called
		//    and capture the Promise passed to it.
		verify(mockDelegateResolver).resolve(eq(HOST), eq(PORT), delegatePromiseCaptor.capture());
		// 4. Simulate the delegate resolver succeeding
		//    Get the captured promise and call its 'succeeded' method with the initial addresses.
		Promise<List<InetSocketAddress>> capturedPromiseForDelegate = delegatePromiseCaptor.getValue();
		assertNotNull(capturedPromiseForDelegate, "Promise passed to delegate resolver should not be null");
		capturedPromiseForDelegate.succeeded(initialAddresses);
		// 5. Verify that SecurityDnsHandler.handleInetSocketAddresses was called
		verify(mockSecurityDnsHandler).handleInetSocketAddresses(initialAddresses, PORT);
		// 6. Verify that the original mockResultPromise.succeeded was called with the filtered list
		verify(mockResultPromise).succeeded(resultListCaptor.capture());
		assertEquals(filteredAddresses, resultListCaptor.getValue(), "The final list of addresses should be the one filtered by the security handler.");
		assertTrue(resultListCaptor.getValue().containsAll(filteredAddresses) && filteredAddresses.containsAll(resultListCaptor.getValue()),
				"Resulting list should exactly match the filtered list.");
		assertFalse(resultListCaptor.getValue().stream().anyMatch(addr -> addr.getAddress().getHostAddress().equals("1.2.3.5")),
				"The IP address '1.2.3.5' should have been filtered out.");
		// Ensure no failures were propagated
		verify(mockResultPromise, never()).failed(any(Throwable.class));
	}

	@Test
	void resolve_whenDelegateFails_shouldPropagateFailureAndNotCallSecurityHandler() {
		// 1. Prepare a sample exception
		Throwable expectedException = new RuntimeException("DNS resolution failed by delegate");

		// 2. Call the method under test
		jettyHttpClientDnsResolver.resolve(HOST, PORT, mockResultPromise);

		// 3. Verify that the delegate resolver's resolve method was called
		//    and capture the Promise passed to it.
		verify(mockDelegateResolver).resolve(eq(HOST), eq(PORT), delegatePromiseCaptor.capture());
		// 4. Simulate the delegate resolver failing
		//    Get the captured promise and call its 'failed' method with the exception.
		Promise<List<InetSocketAddress>> capturedPromiseForDelegate = delegatePromiseCaptor.getValue();
		assertNotNull(capturedPromiseForDelegate, "Promise passed to delegate resolver should not be null");
		capturedPromiseForDelegate.failed(expectedException);
		// 5. Verify that SecurityDnsHandler.handleInetSocketAddresses was NOT called
		verify(mockSecurityDnsHandler, never()).handleInetSocketAddresses(anyList(), anyInt());
		// 6. Verify that the original mockResultPromise.failed was called with the same exception
		verify(mockResultPromise).failed(expectedException);
		// Ensure succeeded was not called
		verify(mockResultPromise, never()).succeeded(anyList());
	}
}
