package org.springframework.security.cas.web;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

public class CasCookieGatewayRequestMatcherTests {

    @Test
    public void testNullServiceProperties() throws Exception {
        try {
            new CasCookieGatewayRequestMatcher(null, null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        	assertEquals("serviceProperties cannot be null", expected.getMessage());
        }
    }

    @Test
    public void testNormalOperationWithNoSSOSession() throws IOException, ServletException {
    	SecurityContextHolder.getContext().setAuthentication(null);
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService("http://localhost/j_spring_cas_security_check");
        CasCookieGatewayRequestMatcher rm = new CasCookieGatewayRequestMatcher(serviceProperties, null);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");

        // First request
        assertTrue(rm.matches(request));
        assertNotNull(request.getSession(false).getAttribute(DefaultGatewayResolverImpl.CONST_CAS_GATEWAY));
        // Second request
        assertFalse(rm.matches(request));
        assertNotNull(request.getSession(false).getAttribute(DefaultGatewayResolverImpl.CONST_CAS_GATEWAY));
    }


    @Test
    public void testGatewayWhenCasAuthenticated() throws IOException, ServletException {
    	SecurityContextHolder.getContext().setAuthentication(null);
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService("http://localhost/j_spring_cas_security_check");
        CasCookieGatewayRequestMatcher rm = new CasCookieGatewayRequestMatcher(serviceProperties, "CAS_TGT_COOKIE_TEST_NAME");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");
        request.setCookies(new Cookie("CAS_TGT_COOKIE_TEST_NAME", "casTGCookieValue"));
        
        assertTrue(rm.matches(request));
        
        MockHttpServletRequest requestWithoutCasCookie = new MockHttpServletRequest("GET", "/some_path");
        requestWithoutCasCookie.setCookies(new Cookie("WRONG_CAS_TGT_COOKIE_TEST_NAME", "casTGCookieValue"));
        
        assertFalse(rm.matches(requestWithoutCasCookie));
    }
    
    @Test
    public void testGatewayWhenAlreadySessionCreated() throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(mock(CasAuthenticationToken.class));

        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService("http://localhost/j_spring_cas_security_check");
        CasCookieGatewayRequestMatcher rm = new CasCookieGatewayRequestMatcher(serviceProperties, "CAS_TGT_COOKIE_TEST_NAME");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");
        assertFalse(rm.matches(request));
    }

    
    @Test
    public void testGatewayWithNoMatchingRequest() throws IOException, ServletException {
    	SecurityContextHolder.getContext().setAuthentication(null);
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService("http://localhost/j_spring_cas_security_check");
        CasCookieGatewayRequestMatcher rm = new CasCookieGatewayRequestMatcher(serviceProperties, "CAS_TGT_COOKIE_TEST_NAME") {
            @Override
            protected boolean performGatewayAuthentication(HttpServletRequest request) {
                return false;
            }
        };
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");

        assertFalse(rm.matches(request));
    }

}