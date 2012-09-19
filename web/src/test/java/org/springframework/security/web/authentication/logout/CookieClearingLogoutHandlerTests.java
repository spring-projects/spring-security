package org.springframework.security.web.authentication.logout;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import javax.servlet.http.Cookie;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

/**
 * @author Luke Taylor
 */
public class CookieClearingLogoutHandlerTests {

    // SEC-2036
    @Test
    public void emptyContextRootIsConverted() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("");
        CookieClearingLogoutHandler handler = new CookieClearingLogoutHandler("my_cookie");
        handler.logout(request, response, mock(Authentication.class));
        assertEquals(1, response.getCookies().length);
        for (Cookie c : response.getCookies()) {
            assertEquals("/", c.getPath());
            assertEquals(0, c.getMaxAge());
        }
    }

    @Test
    public void configuredCookiesAreCleared() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/app");
        CookieClearingLogoutHandler handler = new CookieClearingLogoutHandler("my_cookie", "my_cookie_too");
        handler.logout(request, response, mock(Authentication.class));
        assertEquals(2, response.getCookies().length);
        for (Cookie c : response.getCookies()) {
            assertEquals("/app", c.getPath());
            assertEquals(0, c.getMaxAge());
        }
    }
}
