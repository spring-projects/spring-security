package org.springframework.security.web.authentication;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:org/springframework/security/web/authentication/DelegatingAuthenticationEntryPointTest-context.xml")
public class DelegatinAuthenticationEntryPointContextTest {

    @Autowired
    private DelegatingAuthenticationEntryPoint daep;

    @Autowired
    @Qualifier("firstAEP")
    private AuthenticationEntryPoint firstAEP;

    @Autowired
    @Qualifier("defaultAEP")
    private AuthenticationEntryPoint defaultAEP;

    @Test
    @DirtiesContext
    public void testFirstAEP() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.10");
        request.addHeader("User-Agent", "Mozilla/5.0");
        daep.commence(request, null, null);
        verify(firstAEP).commence(request, null, null);
        verify(defaultAEP, never()).commence(any(HttpServletRequest.class), 
                any(HttpServletResponse.class),
                any(AuthenticationException.class));

    }

    @Test
    @DirtiesContext
    public void testDefaultAEP() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.10");
        daep.commence(request, null, null);
        verify(defaultAEP).commence(request, null, null);
        verify(firstAEP, never()).commence(any(HttpServletRequest.class), 
                any(HttpServletResponse.class),
                any(AuthenticationException.class));

    }

}
