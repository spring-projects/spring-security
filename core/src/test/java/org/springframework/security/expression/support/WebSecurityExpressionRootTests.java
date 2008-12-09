package org.springframework.security.expression.support;

import static org.junit.Assert.*;

import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.Authentication;
import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.security.util.FilterInvocationUtils;

public class WebSecurityExpressionRootTests {
    Mockery jmock = new JUnit4Mockery();

    @Test
    public void ipAddressMatchesForEqualIpAddresses() throws Exception {
        FilterInvocation fi = FilterInvocationUtils.create("/test");
        MockHttpServletRequest request = (MockHttpServletRequest) fi.getHttpRequest();
        request.setRemoteAddr("192.168.1.1");
        WebSecurityExpressionRoot root = new WebSecurityExpressionRoot(jmock.mock(Authentication.class), fi);

        assertTrue(root.hasIpAddress("192.168.1.1"));
    }
}
