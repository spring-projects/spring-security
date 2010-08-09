package org.springframework.security.web.authentication;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.HashMap;

/**
 * @author Luke Taylor
 */
public class ExceptionMappingAuthenticationFailureHandlerTests {

    @Test
    public void defaultTargetUrlIsUsedIfNoMappingExists() throws Exception {
        ExceptionMappingAuthenticationFailureHandler fh = new ExceptionMappingAuthenticationFailureHandler();
        fh.setDefaultFailureUrl("/failed");
        MockHttpServletResponse response = new MockHttpServletResponse();
        fh.onAuthenticationFailure(new MockHttpServletRequest(), response, new BadCredentialsException(""));

        assertEquals("/failed", response.getRedirectedUrl());
    }

    @Test
    public void exceptionMapIsUsedIfMappingExists() throws Exception {
        ExceptionMappingAuthenticationFailureHandler fh = new ExceptionMappingAuthenticationFailureHandler();
        HashMap<String, String> mapping = new HashMap<String, String>();
        mapping.put("org.springframework.security.authentication.BadCredentialsException", "/badcreds");
        fh.setExceptionMappings(mapping);
        fh.setDefaultFailureUrl("/failed");
        MockHttpServletResponse response = new MockHttpServletResponse();
        fh.onAuthenticationFailure(new MockHttpServletRequest(), response, new BadCredentialsException(""));

        assertEquals("/badcreds", response.getRedirectedUrl());
    }

}
