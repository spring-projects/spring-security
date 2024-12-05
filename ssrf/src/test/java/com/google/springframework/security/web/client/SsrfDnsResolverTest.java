package com.google.springframework.security.web.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class SsrfDnsResolverTest {

	@Mock
	private SsrfProtectionFilter ssrfProtectionFilter;

	static class TestableSsrfDnsResolver extends SsrfDnsResolver {

		InetAddress[] addressesToReturn = null;

		public TestableSsrfDnsResolver(List<SsrfProtectionFilter> filterList) {
			super(filterList, false);
		}

		@Override
		protected InetAddress[] resolveAll(String host) throws UnknownHostException {
			return addressesToReturn;
		}

		public void setFilters(List<SsrfProtectionFilter> filterList) {
			filters.clear();
			filters.addAll(filterList);
		}

		public void setReportOnly(boolean b) {
			reportOnly = b;
		}
	}

	@InjectMocks
	private TestableSsrfDnsResolver customDnsResolver = new TestableSsrfDnsResolver(new ArrayList<>());

	@Test
	void testResolveWithValidHost() throws UnknownHostException, HostBlockedException {
		String host = "www.example.com";
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("93.184.216.34")};
		when(ssrfProtectionFilter.filterAddresses(addresses)).thenReturn(addresses);
		customDnsResolver.addressesToReturn = addresses;
		customDnsResolver.setReportOnly(false);
		customDnsResolver.setFilters(List.of(ssrfProtectionFilter));

		InetAddress[] resolvedAddresses = customDnsResolver.resolve(host);

		assertEquals(1, resolvedAddresses.length);
		assertEquals(addresses[0], resolvedAddresses[0]);
	}

	@Test
	void testResolveBlockedHost() throws UnknownHostException, HostBlockedException {
		String host = "192.168.1.1";
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName(host)};
		when(ssrfProtectionFilter.filterAddresses(addresses)).thenThrow(new HostBlockedException("Blocked"));
		customDnsResolver.addressesToReturn = addresses;
		customDnsResolver.setFilters(List.of(ssrfProtectionFilter));
		customDnsResolver.setReportOnly(false);

		UnknownHostException exception = assertThrows(UnknownHostException.class,
				() -> customDnsResolver.resolve(host));
		assertTrue(exception.getMessage().contains("blocked"));

	}

	@Test
	void testResolveBlockedHostInRerpotOnlyMode() throws UnknownHostException, HostBlockedException {
		String host = "192.168.1.1";
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName(host)};
		when(ssrfProtectionFilter.filterAddresses(addresses)).thenThrow(new HostBlockedException("Blocked"));
		customDnsResolver.addressesToReturn = addresses;
		customDnsResolver.setReportOnly(true);
		customDnsResolver.setFilters(List.of(ssrfProtectionFilter));

		InetAddress[] resolvedAddresses = customDnsResolver.resolve(host);

		assertEquals(1, resolvedAddresses.length);
		assertEquals(addresses[0], resolvedAddresses[0]);

	}


	@Test
	void testResolveCanonicalHostname() throws UnknownHostException {
		String host = "www.example.com";
		String resolvedHostname = customDnsResolver.resolveCanonicalHostname(host);
		assertEquals(host, resolvedHostname);
	}
}
