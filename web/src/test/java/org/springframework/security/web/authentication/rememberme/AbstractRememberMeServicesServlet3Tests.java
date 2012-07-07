package org.springframework.security.web.authentication.rememberme;

import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.verifyStatic;
import static org.powermock.api.mockito.PowerMockito.when;

import java.lang.reflect.Method;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServicesTests.MockRememberMeServices;
import org.springframework.util.ReflectionUtils;

/**
 *
 * @author Rob Winch
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({Method.class, ReflectionUtils.class})
public class AbstractRememberMeServicesServlet3Tests {
    @Mock
    private Method method;

    @Before
    public void setUp() throws Exception {
        spy(ReflectionUtils.class);

        when(ReflectionUtils.findMethod(Cookie.class, "setHttpOnly", boolean.class)).thenReturn(method);
    }

    @Test
    public void httpOnlySetInServlet30DefaultConstructor() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getContextPath()).thenReturn("/contextpath");
        HttpServletResponse response = mock(HttpServletResponse.class);
        ArgumentCaptor<Cookie> cookie = ArgumentCaptor.forClass(Cookie.class);
        MockRememberMeServices services = new MockRememberMeServices();
        services.setCookie(new String[] {"mycookie"}, 1000, request, response);
        verify(response).addCookie(cookie.capture());
        verifyStatic();
        ReflectionUtils.invokeMethod(same(method), eq(cookie.getValue()), eq(true));
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
        verifyStatic();
        ReflectionUtils.invokeMethod(same(method), eq(cookie.getValue()), eq(true));
    }
}
