package com.google.springframework.security.web.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import client.dns.SecurityDnsHandler;
import client.HttpComponentsDnsResolver;
import org.apache.hc.client5.http.DnsResolver;
import org.junit.jupiter.api.Test;

class HttpComponentsDnsResolverTests {

	@Test
	void resolveDelegatesAndHandlesAddresses() throws UnknownHostException {
		DnsResolver delegate = mock(DnsResolver.class);
		SecurityDnsHandler securityDnsHandler = mock(SecurityDnsHandler.class);
		HttpComponentsDnsResolver resolver = new HttpComponentsDnsResolver(delegate, securityDnsHandler);

		InetAddress address1 = InetAddress.getByName("192.168.1.1");
		InetAddress address2 = InetAddress.getByName("10.0.0.1");
		InetAddress[] resolvedAddresses = new InetAddress[]{address1, address2};
		when(delegate.resolve("example.com")).thenReturn(resolvedAddresses);

		InetAddress filteredAddress = InetAddress.getByName("127.0.0.1");
		List<InetAddress> handledAddresses = Collections.singletonList(filteredAddress);
		when(securityDnsHandler.handleAddresses(Arrays.asList(resolvedAddresses))).thenReturn(handledAddresses);

		InetAddress[] result = resolver.resolve("example.com");

		assertEquals(1, result.length);
		assertEquals(filteredAddress, result[0]);
		verify(delegate, times(1)).resolve("example.com");
		verify(securityDnsHandler, times(1)).handleAddresses(Arrays.asList(resolvedAddresses));
	}

	@Test
	void resolveUsesSystemDefaultDnsResolverAndHandlesAddresses() throws UnknownHostException {
		SecurityDnsHandler securityDnsHandler = mock(SecurityDnsHandler.class);
		HttpComponentsDnsResolver resolver = new HttpComponentsDnsResolver(securityDnsHandler);

		InetAddress resolvedAddress = InetAddress.getByName("8.8.8.8");
		// We can't directly mock SystemDefaultDnsResolver's resolve method,
		// so we'll rely on its actual behavior for this test.
		// For a more isolated test, we'd mock the delegate.

		InetAddress filteredAddress = InetAddress.getByName("1.1.1.1");
		List<InetAddress> handledAddresses = Collections.singletonList(filteredAddress);
		when(securityDnsHandler.handleAddresses(anyList())).thenReturn(handledAddresses);

		InetAddress[] result = resolver.resolve("google.com"); // Using a real domain for SystemDefaultDnsResolver

		assertEquals(1, result.length);
		assertEquals(filteredAddress, result[0]);
		// We can't easily verify the delegate call here without more complex mocking.
		verify(securityDnsHandler, times(1)).handleAddresses(anyList());
	}

	@Test
	void resolveCanonicalHostnameDelegates() throws UnknownHostException {
		DnsResolver delegate = mock(DnsResolver.class);
		SecurityDnsHandler securityDnsHandler = mock(SecurityDnsHandler.class);
		HttpComponentsDnsResolver resolver = new HttpComponentsDnsResolver(delegate, securityDnsHandler);

		when(delegate.resolveCanonicalHostname("example.com")).thenReturn("canonical.example.com");

		String result = resolver.resolveCanonicalHostname("example.com");

		assertEquals("canonical.example.com", result);
		verify(delegate, times(1)).resolveCanonicalHostname("example.com");
		verify(securityDnsHandler, times(0)).handleAddresses(anyList());
	}

	@Test
	void resolveCanonicalHostnameUsesSystemDefaultDnsResolver() throws UnknownHostException {
		SecurityDnsHandler securityDnsHandler = mock(SecurityDnsHandler.class);
		HttpComponentsDnsResolver resolver = new HttpComponentsDnsResolver(securityDnsHandler);

		// We can't directly mock SystemDefaultDnsResolver's resolveCanonicalHostname,
		// so we'll rely on its actual behavior.

		String result = resolver.resolveCanonicalHostname("localhost"); // Should resolve to "localhost" or similar

		assertEquals("localhost", result); // Assuming default behavior for localhost
		verify(securityDnsHandler, times(0)).handleAddresses(anyList());
	}

	@Test
	void resolveDelegatesUnknownHostException() throws UnknownHostException {
		DnsResolver delegate = mock(DnsResolver.class);
		SecurityDnsHandler securityDnsHandler = mock(SecurityDnsHandler.class);
		HttpComponentsDnsResolver resolver = new HttpComponentsDnsResolver(delegate, securityDnsHandler);

		when(delegate.resolve("unknown.host")).thenThrow(new UnknownHostException("Host not found"));

		assertThrows(UnknownHostException.class, () -> resolver.resolve("unknown.host"));
		verify(securityDnsHandler, times(0)).handleAddresses(anyList());
	}

	@Test
	void resolveCanonicalHostnameDelegatesUnknownHostException() throws UnknownHostException {
		DnsResolver delegate = mock(DnsResolver.class);
		SecurityDnsHandler securityDnsHandler = mock(SecurityDnsHandler.class);
		HttpComponentsDnsResolver resolver = new HttpComponentsDnsResolver(delegate, securityDnsHandler);

		when(delegate.resolveCanonicalHostname("unknown.host")).thenThrow(new UnknownHostException("Host not found"));

		assertThrows(UnknownHostException.class, () -> resolver.resolveCanonicalHostname("unknown.host"));
		verify(securityDnsHandler, times(0)).handleAddresses(anyList());
	}
}
