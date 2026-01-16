package org.springframework.boot.http.client;

import org.apache.hc.client5.http.DnsResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.web.util.matcher.InetAddressFilter;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class HttpComponentsFilteringDnsResolverTest {

	@Mock
	private DnsResolver delegateDnsResolver;

	@Mock
	private InetAddressFilter inetAddressFilter;

	private HttpComponentsFilteringDnsResolver dnsResolver;

	@BeforeEach
	void setUp() {
		dnsResolver = new HttpComponentsFilteringDnsResolver(this.delegateDnsResolver, this.inetAddressFilter);
	}

	@Test
	void resolve_whenDelegateSucceeds_shouldApplyFilterAndReturnFilteredAddresses() throws UnknownHostException {
		String host = "example.com";
		InetAddress address1 = InetAddress.getByName("192.168.1.1"); // Allowed
		InetAddress address2 = InetAddress.getByName("10.0.0.1");    // Disallowed
		InetAddress address3 = InetAddress.getByName("172.16.0.1");  // Allowed

		InetAddress[] resolvedAddresses = new InetAddress[]{address1, address2, address3};
		List<InetAddress> expectedFilteredAddresses = Arrays.asList(address1, address3);

		when(this.delegateDnsResolver.resolve(host)).thenReturn(resolvedAddresses);
		when(this.inetAddressFilter.filter(address1)).thenReturn(true);
		when(this.inetAddressFilter.filter(address2)).thenReturn(false);
		when(this.inetAddressFilter.filter(address3)).thenReturn(true);

		InetAddress[] result = this.dnsResolver.resolve(host);

		assertArrayEquals(expectedFilteredAddresses.toArray(), result);
		verify(this.delegateDnsResolver, times(1)).resolve(host);
		verify(this.inetAddressFilter, times(1)).filter(address1);
		verify(this.inetAddressFilter, times(1)).filter(address2);
		verify(this.inetAddressFilter, times(1)).filter(address3);
	}

	@Test
	void resolve_whenDelegateFails_shouldPropagateFailure() throws UnknownHostException {
		String host = "unknown.host";
		when(this.delegateDnsResolver.resolve(host)).thenThrow(new UnknownHostException("Host not found"));

		assertThrows(UnknownHostException.class, () -> this.dnsResolver.resolve(host));
		verify(this.inetAddressFilter, times(0)).filter(any()); // Filter should not be called
	}

	@Test
	void resolve_whenNoAddressesAreAllowed_shouldReturnEmptyArray() throws UnknownHostException {
		String host = "example.com";
		InetAddress address1 = InetAddress.getByName("10.0.0.1");
		InetAddress address2 = InetAddress.getByName("10.0.0.2");

		InetAddress[] resolvedAddresses = new InetAddress[]{address1, address2};

		when(this.delegateDnsResolver.resolve(host)).thenReturn(resolvedAddresses);
		when(this.inetAddressFilter.filter(address1)).thenReturn(false);
		when(this.inetAddressFilter.filter(address2)).thenReturn(false);

		InetAddress[] result = this.dnsResolver.resolve(host);

		assertEquals(0, result.length);
		verify(this.delegateDnsResolver, times(1)).resolve(host);
		verify(this.inetAddressFilter, times(1)).filter(address1);
		verify(this.inetAddressFilter, times(1)).filter(address2);
	}

	@Test
	void resolveCanonicalHostname_shouldDelegateWithoutFiltering() throws UnknownHostException {
		String host = "example.com";
		String canonicalHost = "canonical.example.com";
		when(this.delegateDnsResolver.resolveCanonicalHostname(host)).thenReturn(canonicalHost);

		String result = this.dnsResolver.resolveCanonicalHostname(host);

		assertEquals(canonicalHost, result);
		verify(this.delegateDnsResolver, times(1)).resolveCanonicalHostname(host);
		verify(this.inetAddressFilter, times(0)).filter(any()); // Filter should not be called
	}

	@Test
	void resolveCanonicalHostname_whenDelegateFails_shouldPropagateFailure() throws UnknownHostException {
		String host = "unknown.host";
		when(this.delegateDnsResolver.resolveCanonicalHostname(host)).thenThrow(new UnknownHostException("Host not found"));

		assertThrows(UnknownHostException.class, () -> this.dnsResolver.resolveCanonicalHostname(host));
		verify(this.inetAddressFilter, times(0)).filter(any()); // Filter should not be called
	}

}
