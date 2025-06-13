package com.google.springframework.security.web.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class IpOrRangeTest {

	// Helper method to create mocked InetAddress instances
	private InetAddress mockInetAddress(String hostname, String ipAddress) throws UnknownHostException {
		InetAddress mocked = Mockito.mock(InetAddress.class);
		Mockito.when(mocked.getHostName()).thenReturn(hostname);
		Mockito.when(mocked.getHostAddress()).thenReturn(ipAddress);
		// Resolve the byte array first. If InetAddress.getByName is statically mocked,
		// this call will be intercepted by that static mock.
		byte[] addressBytes = InetAddress.getByName(ipAddress).getAddress();
		Mockito.when(mocked.getAddress()).thenReturn(addressBytes);
		return mocked;
	}

	@Test
	public void testSingleIpMatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("192.168.1.1");
		InetAddress address = InetAddress.getByName("192.168.1.1");
		assertTrue(ipOrRange.matches(address.getHostAddress(), address));
	}

	@Test
	public void testSingleIpMismatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("192.168.1.1");
		InetAddress address = InetAddress.getByName("192.168.1.2");
		assertFalse(ipOrRange.matches(address.getHostAddress(), address));
	}

	@Test
	public void testCidrMatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("192.168.1.0/24");
		InetAddress address1 = InetAddress.getByName("192.168.1.1");
		InetAddress address2 = InetAddress.getByName("192.168.1.100");
		assertTrue(ipOrRange.matches(address1.getHostAddress(), address1));
		assertTrue(ipOrRange.matches(address2.getHostAddress(), address2));
	}

	@Test
	public void testCidrMismatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("192.168.1.0/24");
		InetAddress address = InetAddress.getByName("192.168.2.1");
		assertFalse(ipOrRange.matches(address.getHostAddress(), address));
	}

	@Test
	public void testCidrMatch_subnet() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("10.0.0.0/8");
		InetAddress address = InetAddress.getByName("10.10.10.10");
		assertTrue(ipOrRange.matches(address.getHostAddress(), address));
	}

	@Test
	public void testCidrMismatch_subnet() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("10.0.0.0/16");
		InetAddress address = InetAddress.getByName("10.1.10.10");
		assertFalse(ipOrRange.matches(address.getHostAddress(), address));
	}

	@Test
	public void testInvalidAddress() {
		Exception ex = assertThrows(IllegalArgumentException.class, () ->
				new IpOrRange("invalid address"), "Exception not triggered");

		assertTrue(ex.getMessage().contains("Failed to parse address"));
	}

	@Test
	public void testHostname() throws UnknownHostException {
		// Assuming "localhost" resolves to 127.0.0.1
		IpOrRange ipOrRange = new IpOrRange("localhost");
		InetAddress address = InetAddress.getByName("127.0.0.1");
		assertTrue(ipOrRange.matches(address.getHostAddress(), address));
	}

	@Test
	public void testIpv6SingleIpMatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("2001:db8::1");
		InetAddress address = InetAddress.getByName("2001:db8::1");
		assertTrue(ipOrRange.matches(address.getHostAddress(), address));
	}

	@Test
	public void testIpv6CidrMatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("2001:db8::/32");
		InetAddress address = InetAddress.getByName("2001:db8:1::1");
		assertTrue(ipOrRange.matches(address.getHostAddress(), address));
	}

	@Test
	public void testHostnameMatch_AllowlistHostname_ToCheckHostname_ExactMatch() throws UnknownHostException {
		try (MockedStatic<InetAddress> mockedStaticInetAddress = Mockito.mockStatic(InetAddress.class)) {
			// Prepare the static mock for the IP string "1.2.3.4" that mockInetAddress will use internally.
			// This mock (ip1234_forBytes) is solely for providing the byte array for "1.2.3.4".
			InetAddress ip1234_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip1234_forBytes.getAddress()).thenReturn(new byte[]{1, 2, 3, 4});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.4")).thenReturn(ip1234_forBytes);

			// Now, mockInetAddress can be called. It will use the above stubbing for InetAddress.getByName("1.2.3.4").
			InetAddress exampleComIp = mockInetAddress("example.com", "1.2.3.4");

			// This stubbing is for the IpOrRange constructor when it resolves "example.com".
			mockedStaticInetAddress.when(() -> InetAddress.getByName("example.com")).thenReturn(exampleComIp);

			IpOrRange ipOrRange = new IpOrRange("example.com"); // Stores "example.com" as hostname
			assertTrue(ipOrRange.matches("example.com", exampleComIp));
		}
	}

	@Test
	public void testHostnameMatch_AllowlistHostname_ToCheckHostname_CaseInsensitiveMatch() throws UnknownHostException {
		try (MockedStatic<InetAddress> mockedStaticInetAddress = Mockito.mockStatic(InetAddress.class)) {
			// Prepare the static mock for the IP string "1.2.3.4" that mockInetAddress will use internally.
			InetAddress ip1234_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip1234_forBytes.getAddress()).thenReturn(new byte[]{1, 2, 3, 4});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.4")).thenReturn(ip1234_forBytes);

			// Now, mockInetAddress can be called.
			InetAddress exampleComIp = mockInetAddress("EXAMPLE.COM", "1.2.3.4"); // rDNS might return uppercase
			mockedStaticInetAddress.when(() -> InetAddress.getByName("example.com")).thenReturn(exampleComIp);

			IpOrRange ipOrRange = new IpOrRange("example.com");

			assertTrue(ipOrRange.matches("EXAMPLE.COM", exampleComIp));
		}
	}

	@Test
	public void testHostnameMatch_AllowlistHostname_ToCheckHostname_SubdomainNoMatch() throws UnknownHostException {
		try (MockedStatic<InetAddress> mockedStaticInetAddress = Mockito.mockStatic(InetAddress.class)) {
			// Prepare static mock for "1.2.3.5" (used by the first mockInetAddress call)
			InetAddress ip1235_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip1235_forBytes.getAddress()).thenReturn(new byte[]{1, 2, 3, 5});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.5")).thenReturn(ip1235_forBytes);
			InetAddress subExampleComIp = mockInetAddress("sub.example.com", "1.2.3.5");

			// Prepare static mock for "1.2.3.4" (used by the second mockInetAddress call)
			InetAddress ip1234_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip1234_forBytes.getAddress()).thenReturn(new byte[]{1, 2, 3, 4});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.4")).thenReturn(ip1234_forBytes);
			// Allowlist entry is for "example.com"
			InetAddress exampleComIp = mockInetAddress("example.com", "1.2.3.4");

			mockedStaticInetAddress.when(() -> InetAddress.getByName("example.com")).thenReturn(exampleComIp);
			mockedStaticInetAddress.when(() -> InetAddress.getByName("sub.example.com")).thenReturn(subExampleComIp);

			IpOrRange ipOrRange = new IpOrRange("example.com");

			assertFalse(ipOrRange.matches("sub.example.com", subExampleComIp));
		}
	}

	@Test
	public void testHostnameMatch_AllowlistHostname_ToCheckIsIPOfHostname_ShouldMatchViaIPFallback() throws UnknownHostException {
		try (MockedStatic<InetAddress> mockedStaticInetAddress = Mockito.mockStatic(InetAddress.class)) {
			// Prepare static mock for "1.2.3.4" that mockInetAddress will use internally
			// to get the byte array.
			InetAddress ip1234_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip1234_forBytes.getAddress()).thenReturn(new byte[]{1, 2, 3, 4});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.4")).thenReturn(ip1234_forBytes);

			InetAddress exampleComIp = mockInetAddress("example.com", "1.2.3.4");
			// Now exampleComIp is fully mocked, including its getAddress() method.

			mockedStaticInetAddress.when(() -> InetAddress.getByName("example.com")).thenReturn(exampleComIp);
			IpOrRange ipOrRange = new IpOrRange("example.com"); // hostname = "example.com", address = 1.2.3.4

			// toCheckAddressString is an IP, toCheckInetAddress is the InetAddress for that IP
			assertTrue(ipOrRange.matches("1.2.3.4", exampleComIp));
		}
	}

	@Test
	public void testHostnameMatch_AllowlistHostname_ToCheckIsDifferentIP_ShouldNotMatch() throws UnknownHostException {
		try (MockedStatic<InetAddress> mockedStaticInetAddress = Mockito.mockStatic(InetAddress.class)) {
			// Prepare static mock for "1.2.3.4" (used by the first mockInetAddress call)
			InetAddress ip1234_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip1234_forBytes.getAddress()).thenReturn(new byte[]{1, 2, 3, 4});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.4")).thenReturn(ip1234_forBytes);
			InetAddress exampleComIp = mockInetAddress("example.com", "1.2.3.4");

			// Prepare static mock for "1.2.3.5" (used by the second mockInetAddress call)
			InetAddress ip1235_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip1235_forBytes.getAddress()).thenReturn(new byte[]{1, 2, 3, 5});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.5")).thenReturn(ip1235_forBytes);
			InetAddress differentIp = mockInetAddress("other.com", "1.2.3.5"); // or just an IP

			mockedStaticInetAddress.when(() -> InetAddress.getByName("example.com")).thenReturn(exampleComIp);

			IpOrRange ipOrRange = new IpOrRange("example.com");

			assertFalse(ipOrRange.matches("1.2.3.5", differentIp));
		}
	}

	@Test
	public void testHostnameMatch_AllowlistIP_ToCheckIsHostnameResolvingToIP_ShouldMatchViaIP() throws UnknownHostException {
		try (MockedStatic<InetAddress> mockedStaticInetAddress = Mockito.mockStatic(InetAddress.class)) {
			// Prepare static mock for "1.2.3.4" that mockInetAddress will use internally
			// to get the byte array.
			InetAddress ip1234_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip1234_forBytes.getAddress()).thenReturn(new byte[]{1, 2, 3, 4});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.4")).thenReturn(ip1234_forBytes);

			InetAddress targetIp = mockInetAddress("example.com", "1.2.3.4"); // The IP we are interested in
			// Mock resolution for "example.com"
			mockedStaticInetAddress.when(() -> InetAddress.getByName("example.com")).thenReturn(targetIp);
			// Mock resolution for "1.2.3.4" (used by IpOrRange constructor)
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.4")).thenReturn(targetIp);

			IpOrRange ipOrRange = new IpOrRange("1.2.3.4"); // hostname = null, address = 1.2.3.4

			// toCheckAddressString is "example.com", toCheckInetAddress is the InetAddress for "example.com"
			assertTrue(ipOrRange.matches("example.com", targetIp));
		}
	}

	@Test
	public void testHostnameMatch_AllowlistIP_ToCheckIsHostnameResolvingToDifferentIP_ShouldNotMatch() throws UnknownHostException {
		try (MockedStatic<InetAddress> mockedStaticInetAddress = Mockito.mockStatic(InetAddress.class)) {
			// Prepare static mock for "1.2.3.4" (used by the first mockInetAddress call)
			InetAddress ip1234_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip1234_forBytes.getAddress()).thenReturn(new byte[]{1, 2, 3, 4});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.4")).thenReturn(ip1234_forBytes);
			InetAddress allowlistIp = mockInetAddress("ip.only", "1.2.3.4");

			// Prepare static mock for "5.6.7.8" (used by the second mockInetAddress call)
			InetAddress ip5678_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip5678_forBytes.getAddress()).thenReturn(new byte[]{5, 6, 7, 8});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("5.6.7.8")).thenReturn(ip5678_forBytes);
			InetAddress otherHostnameIp = mockInetAddress("other.com", "5.6.7.8");


			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.4")).thenReturn(allowlistIp);
			mockedStaticInetAddress.when(() -> InetAddress.getByName("other.com")).thenReturn(otherHostnameIp);

			IpOrRange ipOrRange = new IpOrRange("1.2.3.4"); // hostname = null, address = 1.2.3.4

			assertFalse(ipOrRange.matches("other.com", otherHostnameIp));
		}
	}

	// It might be good to update the existing testHostname to reflect new signature and intent
	@Test
	public void testHostname_ResolvesToIp_MatchesViaIpFallback() throws UnknownHostException {
		// This test now checks that an allowlist entry "localhost" (which stores "localhost" as hostname)
		// correctly matches the IP "127.0.0.1" via IP fallback logic.
		try (MockedStatic<InetAddress> mockedStaticInetAddress = Mockito.mockStatic(InetAddress.class)) {
			// 1. Prepare the static mock for the IP string "127.0.0.1" that mockInetAddress will use internally.
			// This is needed because mockInetAddress calls InetAddress.getByName("127.0.0.1").getAddress().
			InetAddress ip127_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip127_forBytes.getAddress()).thenReturn(new byte[]{127, 0, 0, 1});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("127.0.0.1")).thenReturn(ip127_forBytes);

			// 2. Create the InetAddress object that represents "localhost" resolving to "127.0.0.1".
			// This will be used both for the IpOrRange constructor (via stubbing) and for the matches() call.
			InetAddress localhostIp = mockInetAddress("localhost", "127.0.0.1");

			// 3. Mock what InetAddress.getByName("localhost") returns for the IpOrRange constructor.
			mockedStaticInetAddress.when(() -> InetAddress.getByName("localhost")).thenReturn(localhostIp);

			IpOrRange ipOrRange = new IpOrRange("localhost"); // Constructor uses the stub above.

			// 4. Assert that matching "127.0.0.1" (IP string) against the `localhostIp` object works.
			assertTrue(ipOrRange.matches("127.0.0.1", localhostIp));
		}
	}

	@Test
	public void testHostnameMatch_AllowlistDomain_ToCheckWwwDomain_ShouldMatch() throws UnknownHostException {
		try (MockedStatic<InetAddress> mockedStaticInetAddress = Mockito.mockStatic(InetAddress.class)) {
			// Prepare static mock for "1.2.3.4" (used by mockInetAddress for "www.example.com")
			InetAddress ip1234_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip1234_forBytes.getAddress()).thenReturn(new byte[]{1, 2, 3, 4});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.4")).thenReturn(ip1234_forBytes);
			InetAddress wwwExampleComIp = mockInetAddress("www.example.com", "1.2.3.4");

			// Prepare static mock for "example.com" (used by IpOrRange constructor and potentially mockInetAddress)
			// If mockInetAddress was called for "example.com", it would also use ip1234_forBytes via "1.2.3.4"
			InetAddress exampleComIpForConstructor = mockInetAddress("example.com", "1.2.3.4");
			mockedStaticInetAddress.when(() -> InetAddress.getByName("example.com")).thenReturn(exampleComIpForConstructor);

			IpOrRange ipOrRange = new IpOrRange("example.com"); // Stored hostname: "example.com"
			assertTrue(ipOrRange.matches("www.example.com", wwwExampleComIp)); // Check: "www.example.com"
		}
	}

	@Test
	public void testHostnameMatch_AllowlistWwwDomain_ToCheckDomain_ShouldMatch() throws UnknownHostException {
		try (MockedStatic<InetAddress> mockedStaticInetAddress = Mockito.mockStatic(InetAddress.class)) {
			// Prepare static mock for "1.2.3.4" (used by mockInetAddress for "example.com")
			InetAddress ip1234_forBytes = Mockito.mock(InetAddress.class);
			Mockito.when(ip1234_forBytes.getAddress()).thenReturn(new byte[]{1, 2, 3, 4});
			mockedStaticInetAddress.when(() -> InetAddress.getByName("1.2.3.4")).thenReturn(ip1234_forBytes);
			InetAddress exampleComIp = mockInetAddress("example.com", "1.2.3.4");

			// Prepare static mock for "www.example.com" (used by IpOrRange constructor and potentially mockInetAddress)
			InetAddress wwwExampleComIpForConstructor = mockInetAddress("www.example.com", "1.2.3.4");
			mockedStaticInetAddress.when(() -> InetAddress.getByName("www.example.com")).thenReturn(wwwExampleComIpForConstructor);

			IpOrRange ipOrRange = new IpOrRange("www.example.com"); // Stored hostname: "www.example.com"
			assertTrue(ipOrRange.matches("example.com", exampleComIp)); // Check: "example.com"
		}
	}
}
