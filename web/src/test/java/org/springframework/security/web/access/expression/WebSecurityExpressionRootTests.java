package org.springframework.security.web.access.expression;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

/**
 * Tests for {@link WebSecurityExpressionRoot}.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class WebSecurityExpressionRootTests {

    @Test
    public void ipAddressMatchesForEqualIpAddresses() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/test");
        // IPv4
        request.setRemoteAddr("192.168.1.1");
        WebSecurityExpressionRoot root = new WebSecurityExpressionRoot(mock(Authentication.class),
                new FilterInvocation(request, mock(HttpServletResponse.class), mock(FilterChain.class)));

        assertTrue(root.hasIpAddress("192.168.1.1"));

        // IPv6 Address
        request.setRemoteAddr("fa:db8:85a3::8a2e:370:7334");
        assertTrue(root.hasIpAddress("fa:db8:85a3::8a2e:370:7334"));
    }

    @Test
    public void addressesInIpRangeMatch() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/test");
        WebSecurityExpressionRoot root = new WebSecurityExpressionRoot(mock(Authentication.class),
                new FilterInvocation(request, mock(HttpServletResponse.class), mock(FilterChain.class)));
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
