package com.google.springframework.security.web.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;

class FilterUtilsTest {

	@Test
	public void testIsInternalIpOnLoopback() throws UnknownHostException {
		InetAddress addr = InetAddress.getByName("127.0.0.1");
		assertTrue(FilterUtils.isInternalIp(addr));
	}

	@Test
	public void testIsInternalIpOnIpv4_10x() throws UnknownHostException {
		InetAddress addr = InetAddress.getByName("10.1.2.3");
		assertTrue(FilterUtils.isInternalIp(addr));
	}

	@Test
	public void testIsInternalIpOnIpv4_192x() throws UnknownHostException {
		InetAddress addr = InetAddress.getByName("192.168.10.20");
		assertTrue(FilterUtils.isInternalIp(addr));
	}

	@Test
	public void testIsInternalIpOnIpv4_172x() throws UnknownHostException {
		InetAddress addr = InetAddress.getByName("172.16.0.1");
		assertTrue(FilterUtils.isInternalIp(addr));
	}

	@Test
	public void testIsInternalIp_ipv6() throws UnknownHostException {
		InetAddress addr = InetAddress.getByName("fd00::1");
		assertTrue(FilterUtils.isInternalIp(addr));
	}

	@Test
	public void testIsInternalIpOnPublicIpv4() throws UnknownHostException {
		InetAddress addr = InetAddress.getByName("8.8.8.8");
		assertFalse(FilterUtils.isInternalIp(addr));
	}

	@Test
	public void testIsInternalIpOnPublicIpv6() throws UnknownHostException {
		InetAddress addr = InetAddress.getByName("2001:4860:4860::8888");
		assertFalse(FilterUtils.isInternalIp(addr));
	}

}
