package com.google.springframework.security.web.ssrf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class CustomDnsResolverTest {

	@Mock
	private SsrfProtectionConfig ssrfProtectionConfig;

	@Mock
	private SsrfProtectionFilter ssrfProtectionFilter;


	static class TestableCustomDnsResolver extends CustomDnsResolver {

		InetAddress[] addressesToReturn = null;

		public TestableCustomDnsResolver(SsrfProtectionConfig ssrfProtectionConfig) {
			super(ssrfProtectionConfig);
		}

		@Override
		protected InetAddress[] resolveAll(String host) throws UnknownHostException {
			return addressesToReturn;
		}
	}

	@InjectMocks
	private TestableCustomDnsResolver customDnsResolver;

	@Test
	void testResolve_validHost() throws UnknownHostException, HostBlockedException {
		String host = "www.example.com";
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName("93.184.216.34")};
		when(ssrfProtectionConfig.getFilter()).thenReturn(ssrfProtectionFilter);
		when(ssrfProtectionFilter.filter(addresses)).thenReturn(addresses);
		customDnsResolver.addressesToReturn = addresses;

		InetAddress[] resolvedAddresses = customDnsResolver.resolve(host);

		assertEquals(1, resolvedAddresses.length);
		assertEquals(addresses[0], resolvedAddresses[0]);
	}

	@Test
	void testResolve_blockedHost() throws UnknownHostException, HostBlockedException {
		String host = "192.168.1.1";
		InetAddress[] addresses = new InetAddress[]{InetAddress.getByName(host)};
		when(ssrfProtectionConfig.getFilter()).thenReturn(ssrfProtectionFilter);
		when(ssrfProtectionFilter.filter(addresses)).thenThrow(new HostBlockedException("Blocked"));

		customDnsResolver.addressesToReturn = addresses;

		UnknownHostException exception = assertThrows(UnknownHostException.class,
				() -> customDnsResolver.resolve(host));
		assertTrue(exception.getMessage().contains("blocked"));

	}


	@Test
	void testResolveCanonicalHostname() throws UnknownHostException {
		String host = "www.example.com";
		String resolvedHostname = customDnsResolver.resolveCanonicalHostname(host);
		assertEquals(host, resolvedHostname); // Since the method is not fully implemented yet
	}
}
