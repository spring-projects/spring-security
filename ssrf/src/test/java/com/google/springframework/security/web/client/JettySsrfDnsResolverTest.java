package com.google.springframework.security.web.client;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import org.eclipse.jetty.util.Promise;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class JettySsrfDnsResolverTest {

	@Mock
	private SsrfProtectionFilter ssrfProtectionFilter;

	static class TestableJettySsrfDnsResolver extends JettySsrfDnsResolver {

		InetAddress[] addressesToReturn = null;

		public TestableJettySsrfDnsResolver(List<SsrfProtectionFilter> filters) {
			super(filters, false);
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
	private TestableJettySsrfDnsResolver customDnsResolver = new TestableJettySsrfDnsResolver(new ArrayList<>());

	@Test
	void testResolveWithValidHost()
			throws UnknownHostException, HostBlockedException, ExecutionException, InterruptedException {
		String host = "www.example.com";
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("93.184.216.34")};
		when(ssrfProtectionFilter.filterAddresses(addresses)).thenReturn(addresses);
		customDnsResolver.addressesToReturn = addresses;
		customDnsResolver.setFilters(List.of(ssrfProtectionFilter));

		Promise.Completable<List<InetSocketAddress>> promise = new Promise.Completable<>();

		customDnsResolver.resolve(host, 80, promise);

		assertTrue(promise.isDone());
		List<InetSocketAddress> resolvedAddresses = promise.get();
		assertEquals(1, resolvedAddresses.size());
		assertEquals(addresses[0], resolvedAddresses.get(0).getAddress());
		assertEquals(80, resolvedAddresses.get(0).getPort());
	}

	@Test
	void testResolveBlockedHostInRerpotOnlyMode()
			throws UnknownHostException, HostBlockedException, ExecutionException, InterruptedException {
		String host = "192.168.1.1";
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName(host)};
		when(ssrfProtectionFilter.filterAddresses(addresses)).thenThrow(new HostBlockedException("Blocked"));
		customDnsResolver.addressesToReturn = addresses;
		customDnsResolver.setReportOnly(true);
		customDnsResolver.setFilters(List.of(ssrfProtectionFilter));

		Promise.Completable<List<InetSocketAddress>> promise = new Promise.Completable<>();

		customDnsResolver.resolve(host, 443, promise);

		assertTrue(promise.isDone());
		List<InetSocketAddress> resolvedAddresses = promise.get();

		assertEquals(1, resolvedAddresses.size());
		assertEquals(addresses[0], resolvedAddresses.get(0).getAddress());
		assertEquals(443, resolvedAddresses.get(0).getPort());
	}

	@Test
	void testResolveBlockedHost()
			throws UnknownHostException, HostBlockedException, ExecutionException, InterruptedException {
		String host = "192.168.1.1";
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName(host)};
		when(ssrfProtectionFilter.filterAddresses(addresses)).thenThrow(new HostBlockedException("Blocked"));
		customDnsResolver.addressesToReturn = addresses;
		customDnsResolver.setFilters(List.of(ssrfProtectionFilter));
		customDnsResolver.setReportOnly(false);

		Promise.Completable<List<InetSocketAddress>> promise = new Promise.Completable<>();

		customDnsResolver.resolve(host, 443, promise);
		promise.whenComplete((res, exc) -> {
			assertTrue(exc.getMessage().contains("was blocked"));
		});
		assertTrue(promise.isCompletedExceptionally());
	}
}


