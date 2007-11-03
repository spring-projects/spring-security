package org.springframework.security.ui.rememberme;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;

import static org.junit.Assert.*;
import org.junit.Test;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class AbstractRememberMeServicesTests {
    User joe = new User("joe", "password", true, true,true,true, new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A")});

    @Test(expected = InvalidCookieException.class)
    public void nonBase64CookieShouldBeDetected() {
        new MockRememberMeServices().decodeCookie("nonBase64CookieValue%");
    }

    @Test
    public void cookieShouldBeCorrectlyEncodedAndDecoded() {
        String[] cookie = new String[] {"the", "cookie", "tokens", "blah"};
        MockRememberMeServices services = new MockRememberMeServices();

        String encoded = services.encodeCookie(cookie);
        // '=' aren't alowed in version 0 cookies.  
        assertFalse(encoded.endsWith("="));
        String[] decoded = services.decodeCookie(encoded);

        assertEquals(4, decoded.length);
        assertEquals("the", decoded[0]);
        assertEquals("cookie", decoded[1]);
        assertEquals("tokens", decoded[2]);
        assertEquals("blah", decoded[3]);        
    }

    @Test
    public void autoLoginShouldReturnNullIfNoLoginCookieIsPresented() {
        MockRememberMeServices services = new MockRememberMeServices();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertNull(services.autoLogin(request, response));

        // shouldn't try to invalidate our cookie
        assertNull(response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_PERSISTENT_REMEMBER_ME_COOKIE_KEY));

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        // set non-login cookie
        request.setCookies(new Cookie[] {new Cookie("mycookie", "cookie")});
        assertNull(services.autoLogin(request, response));
        assertNull(response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_PERSISTENT_REMEMBER_ME_COOKIE_KEY));        
    }

    @Test
    public void successfulAutoLoginReturnsExpectedAuthentication() {
        MockRememberMeServices services = new MockRememberMeServices();
        services.setUserDetailsService(new MockAuthenticationDao(joe, false));
        assertNotNull(services.getUserDetailsService());

        MockHttpServletRequest request = new MockHttpServletRequest();

        request.setCookies(createLoginCookie("cookie:1:2"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNotNull(result);
    }

    @Test
    public void autoLoginShouldFailIfInvalidCookieExceptionIsRaised() {
        MockRememberMeServices services = new MockRememberMeServices();
        services.setUserDetailsService(new MockAuthenticationDao(joe, true));

        MockHttpServletRequest request = new MockHttpServletRequest();
        // Wrong number of tokes
        request.setCookies(createLoginCookie("cookie:1"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);

        assertCookieCancelled(response);
    }

    @Test
    public void autoLoginShouldFailIfUserNotFound() {
        MockRememberMeServices services = new MockRememberMeServices();
        services.setUserDetailsService(new MockAuthenticationDao(joe, true));        

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(createLoginCookie("cookie:1:2"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);

        assertCookieCancelled(response);
    }

    @Test
    public void autoLoginShouldFailIfUserAccountIsLocked() {
        MockRememberMeServices services = new MockRememberMeServices();
        User joeLocked = new User("joe", "password",false,true,true,true,joe.getAuthorities());
        services.setUserDetailsService(new MockAuthenticationDao(joeLocked, false));        

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(createLoginCookie("cookie:1:2"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);

        assertCookieCancelled(response);
    }

    @Test
    public void loginFailShouldCancelCookie() {
        MockRememberMeServices services = new MockRememberMeServices();
        services.setUserDetailsService(new MockAuthenticationDao(joe, true));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("contextpath");
        request.setCookies(createLoginCookie("cookie:1:2"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        services.loginFail(request, response);

        assertCookieCancelled(response);
    }

    @Test(expected = CookieTheftException.class)
    public void cookieTheftExceptionShouldBeRethrown() {
        MockRememberMeServices services = new MockRememberMeServices() {
            protected String processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request, HttpServletResponse response) {
                throw new CookieTheftException("Pretending cookie was stolen");
            }
        };

        services.setUserDetailsService(new MockAuthenticationDao(joe, false));
        MockHttpServletRequest request = new MockHttpServletRequest();

        request.setCookies(createLoginCookie("cookie:1:2"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        services.autoLogin(request, response);
    }

    @Test
    public void loginSuccessCallsOnLoginSuccessCorrectly() {
        MockRememberMeServices services = new MockRememberMeServices();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = new UsernamePasswordAuthenticationToken("joe","password");

        // No parameter set
        services = new MockRememberMeServices();
        services.loginSuccess(request, response, auth);
        assertFalse(services.loginSuccessCalled);

        // Parameter set to true
        services = new MockRememberMeServices();
        request.setParameter(MockRememberMeServices.DEFAULT_PARAMETER, "true");
        services.loginSuccess(request, response, auth);
        assertTrue(services.loginSuccessCalled);

        // Different parameter name, set to true
        services = new MockRememberMeServices();
        services.setParameter("my_parameter");
        request.setParameter("my_parameter", "true");
        services.loginSuccess(request, response, auth);
        assertTrue(services.loginSuccessCalled);


        // Parameter set to false
        services = new MockRememberMeServices();
        request.setParameter(MockRememberMeServices.DEFAULT_PARAMETER, "false");
        services.loginSuccess(request, response, auth);
        assertFalse(services.loginSuccessCalled);

        // alwaysRemember set to true
        services = new MockRememberMeServices();
        services.setAlwaysRemember(true);
        services.loginSuccess(request, response, auth);
        assertTrue(services.loginSuccessCalled);

    }

    @Test
    public void makeValidCookieUsesCorrectNamePathAndValue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("contextpath");
        MockRememberMeServices services = new MockRememberMeServices();
        services.setCookieName("mycookiename");
        Cookie cookie = services.makeValidCookie("mycookie", request, 1000);

        assertTrue(cookie.getValue().equals("mycookie"));
        assertTrue(cookie.getName().equals("mycookiename"));
        assertTrue(cookie.getPath().equals("contextpath"));

    }


    private Cookie[] createLoginCookie(String cookieToken) {
        MockRememberMeServices services = new MockRememberMeServices();
        Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_PERSISTENT_REMEMBER_ME_COOKIE_KEY,
                services.encodeCookie(StringUtils.delimitedListToStringArray(cookieToken, ":")));

        return new Cookie[] {cookie};
    }

    private void assertCookieCancelled(MockHttpServletResponse response) {
        Cookie returnedCookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_PERSISTENT_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    //~ Inner Classes ==================================================================================================

    private class MockRememberMeServices extends AbstractRememberMeServices {
        boolean loginSuccessCalled;

        private MockRememberMeServices() {
            setKey("key");
        }

        protected void onLoginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {
            loginSuccessCalled = true;
        }

        protected String processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request, HttpServletResponse response) throws RememberMeAuthenticationException {
            if(cookieTokens.length != 3) {
                throw new InvalidCookieException("deliberate exception");
            }

            return "joe";
        }
    }

    private class MockAuthenticationDao implements UserDetailsService {
        private UserDetails toReturn;
        private boolean throwException;

        public MockAuthenticationDao(UserDetails toReturn, boolean throwException) {
            this.toReturn = toReturn;
            this.throwException = throwException;
        }

        public UserDetails loadUserByUsername(String username) {
            if (throwException) {
                throw new UsernameNotFoundException("as requested by mock");
            }

            return toReturn;
        }
    }
}
