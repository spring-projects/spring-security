package com.google.springframework.security.web.ssrf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;

public class IpOrRangeTest {

	@Test
	public void testSingleIpMatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("192.168.1.1");
		InetAddress address = InetAddress.getByName("192.168.1.1");
		assertTrue(ipOrRange.matches(address));
	}

	@Test
	public void testSingleIpMismatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("192.168.1.1");
		InetAddress address = InetAddress.getByName("192.168.1.2");
		assertFalse(ipOrRange.matches(address));
	}

	@Test
	public void testCidrMatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("192.168.1.0/24");
		InetAddress address1 = InetAddress.getByName("192.168.1.1");
		InetAddress address2 = InetAddress.getByName("192.168.1.100");
		assertTrue(ipOrRange.matches(address1));
		assertTrue(ipOrRange.matches(address2));
	}

	@Test
	public void testCidrMismatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("192.168.1.0/24");
		InetAddress address = InetAddress.getByName("192.168.2.1");
		assertFalse(ipOrRange.matches(address));
	}

	@Test
	public void testCidrMatch_subnet() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("10.0.0.0/8");
		InetAddress address = InetAddress.getByName("10.10.10.10");
		assertTrue(ipOrRange.matches(address));
	}

	@Test
	public void testCidrMismatch_subnet() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("10.0.0.0/16");
		InetAddress address = InetAddress.getByName("10.1.10.10");
		assertFalse(ipOrRange.matches(address));
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
		assertTrue(ipOrRange.matches(address));
	}

	@Test
	public void testIpv6SingleIpMatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("2001:db8::1");
		InetAddress address = InetAddress.getByName("2001:db8::1");
		assertTrue(ipOrRange.matches(address));
	}

	@Test
	public void testIpv6CidrMatch() throws UnknownHostException {
		IpOrRange ipOrRange = new IpOrRange("2001:db8::/32");
		InetAddress address = InetAddress.getByName("2001:db8:1::1");
		assertTrue(ipOrRange.matches(address));
	}

}

