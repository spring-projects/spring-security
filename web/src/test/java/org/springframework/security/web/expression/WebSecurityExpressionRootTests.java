package org.springframework.security.web.expression;

import static org.junit.Assert.*;

import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.Authentication;
import org.springframework.security.web.intercept.FilterInvocation;
import org.springframework.security.web.util.FilterInvocationUtils;

/**
 * Tests for {@link WebSecurityExpressionRoot}.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class WebSecurityExpressionRootTests {
    Mockery jmock = new JUnit4Mockery();

    @Test
    public void ipAddressMatchesForEqualIpAddresses() throws Exception {
        FilterInvocation fi = FilterInvocationUtils.create("/test");
        MockHttpServletRequest request = (MockHttpServletRequest) fi.getHttpRequest();
        // IPv4
        request.setRemoteAddr("192.168.1.1");
        WebSecurityExpressionRoot root = new WebSecurityExpressionRoot(jmock.mock(Authentication.class), fi);

        assertTrue(root.hasIpAddress("192.168.1.1"));

        // IPv6 Address
        request.setRemoteAddr("fa:db8:85a3::8a2e:370:7334");
        assertTrue(root.hasIpAddress("fa:db8:85a3::8a2e:370:7334"));
    }

    @Test
    public void addressesInIpRangeMatch() throws Exception {
        FilterInvocation fi = FilterInvocationUtils.create("/test");
        MockHttpServletRequest request = (MockHttpServletRequest) fi.getHttpRequest();
        WebSecurityExpressionRoot root = new WebSecurityExpressionRoot(jmock.mock(Authentication.class), fi);
        for (int i=0; i < 255; i++) {
            request.setRemoteAddr("192.168.1." + i);
            assertTrue(root.hasIpAddress("192.168.1.0/24"));
        }

        request.setRemoteAddr("192.168.1.127");
        // 25 = FF FF FF 80
        assertTrue(root.hasIpAddress("192.168.1.0/25"));
        // encroach on the mask
        request.setRemoteAddr("192.168.1.128");
        assertFalse(root.hasIpAddress("192.168.1.0/25"));
        request.setRemoteAddr("192.168.1.255");
        assertTrue(root.hasIpAddress("192.168.1.128/25"));
        assertTrue(root.hasIpAddress("192.168.1.192/26"));
        assertTrue(root.hasIpAddress("192.168.1.224/27"));
        assertTrue(root.hasIpAddress("192.168.1.240/27"));
        assertTrue(root.hasIpAddress("192.168.1.255/32"));

        request.setRemoteAddr("202.24.199.127");
        assertTrue(root.hasIpAddress("202.24.0.0/14"));
        request.setRemoteAddr("202.25.179.135");
        assertTrue(root.hasIpAddress("202.24.0.0/14"));
        request.setRemoteAddr("202.26.179.135");
        assertTrue(root.hasIpAddress("202.24.0.0/14"));
    }

}
