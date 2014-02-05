package org.springframework.security.cas.web;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import junit.framework.Assert;

import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

public class DefaultCasGatewayRequestMatcherTests {

    @Test
    public void testNullServiceProperties() throws Exception {
        try {
            new DefaultCasGatewayRequestMatcher(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            Assert.assertEquals("serviceProperties cannot be null", expected.getMessage());
        }
    }

    @Test
    public void testNormalOperationWithNoSSOSession() throws IOException, ServletException {
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService("http://localhost/j_spring_cas_security_check");
        DefaultCasGatewayRequestMatcher rm = new DefaultCasGatewayRequestMatcher(serviceProperties);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");

        // First request
        Assert.assertTrue(rm.matches(request));
        Assert.assertNotNull(request.getSession(false).getAttribute(DefaultGatewayResolverImpl.CONST_CAS_GATEWAY));
        // Second request
        Assert.assertFalse(rm.matches(request));
        Assert.assertNull(request.getSession(false).getAttribute(DefaultGatewayResolverImpl.CONST_CAS_GATEWAY));
    }

    @Test
    public void testGatewayWhenAlreadyCasAuthenticated() throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(mock(CasAuthenticationToken.class));

        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService("http://localhost/j_spring_cas_security_check");
        DefaultCasGatewayRequestMatcher rm = new DefaultCasGatewayRequestMatcher(serviceProperties);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");

        Assert.assertFalse(rm.matches(request));
    }

    @Test
    public void testGatewayWithNoMatchingRequest() throws IOException, ServletException {
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService("http://localhost/j_spring_cas_security_check");
        DefaultCasGatewayRequestMatcher rm = new DefaultCasGatewayRequestMatcher(serviceProperties) {
            @Override
            protected boolean performGatewayAuthentication(HttpServletRequest request) {
                return false;
            }
        };
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");

        Assert.assertFalse(rm.matches(request));
    }

}
