package org.springframework.security.web.authentication.rememberme;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServicesTests.MockRememberMeServices;
import org.springframework.util.ReflectionUtils;

/**
 * Note: This test will fail in the IDE since it needs to be ran with servlet 3.0 and servlet 2.5 is also on the classpath.
 *
 * @author Rob Winch
 */
public class AbstractRememberMeServicesServlet3Tests {

    @Test
    public void httpOnlySetInServlet30DefaultConstructor() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getContextPath()).thenReturn("/contextpath");
        HttpServletResponse response = mock(HttpServletResponse.class);
        ArgumentCaptor<Cookie> cookie = ArgumentCaptor.forClass(Cookie.class);
        MockRememberMeServices services = new MockRememberMeServices();
        services.setCookie(new String[] {"mycookie"}, 1000, request, response);
        verify(response).addCookie(cookie.capture());
        Cookie rememberme = cookie.getValue();
        assertTrue((Boolean)ReflectionUtils.invokeMethod(rememberme.getClass().getMethod("isHttpOnly"),rememberme));
    }

    @Test
    public void httpOnlySetInServlet30() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getContextPath()).thenReturn("/contextpath");
        HttpServletResponse response = mock(HttpServletResponse.class);
        ArgumentCaptor<Cookie> cookie = ArgumentCaptor.forClass(Cookie.class);
        MockRememberMeServices services = new MockRememberMeServices("key",mock(UserDetailsService.class));
        services.setCookie(new String[] {"mycookie"}, 1000, request, response);
        verify(response).addCookie(cookie.capture());
        Cookie rememberme = cookie.getValue();
        assertTrue((Boolean)ReflectionUtils.invokeMethod(rememberme.getClass().getMethod("isHttpOnly"),rememberme));
    }
}
