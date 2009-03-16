package org.springframework.security.ui.rememberme;

import static org.junit.Assert.*;
import static org.springframework.security.ui.rememberme.AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY;

import java.util.Date;

import javax.servlet.http.Cookie;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class PersistentTokenBasedRememberMeServicesTests {
    private PersistentTokenBasedRememberMeServices services;

    @Before
    public void setUpData() throws Exception {
        services = new PersistentTokenBasedRememberMeServices();
        services.setCookieName("mycookiename");
        services.setUserDetailsService(
                new AbstractRememberMeServicesTests.MockUserDetailsService(AbstractRememberMeServicesTests.joe, false));
    }

    @Test(expected = InvalidCookieException.class)
    public void loginIsRejectedWithWrongNumberOfCookieTokens() {
        services.processAutoLoginCookie(new String[] {"series", "token", "extra"}, new MockHttpServletRequest(),
                new MockHttpServletResponse());
    }

    @Test(expected = RememberMeAuthenticationException.class)
    public void loginIsRejectedWhenNoTokenMatchingSeriesIsFound() {
        services.setTokenRepository(new MockTokenRepository(null));
        services.processAutoLoginCookie(new String[] {"series", "token"}, new MockHttpServletRequest(),
                new MockHttpServletResponse());
    }

    @Test(expected = RememberMeAuthenticationException.class)
    public void loginIsRejectedWhenTokenIsExpired() {
        MockTokenRepository repo =
                new MockTokenRepository(new PersistentRememberMeToken("joe", "series","token", new Date()));
        services.setTokenRepository(repo);
        services.setTokenValiditySeconds(1);
        try {
            Thread.sleep(1100);
        } catch (InterruptedException e) {
        }
        services.setTokenRepository(repo);

        services.processAutoLoginCookie(new String[] {"series", "token"}, new MockHttpServletRequest(),
                new MockHttpServletResponse());
    }

    @Test(expected = CookieTheftException.class)
    public void cookieTheftIsDetectedWhenSeriesAndTokenDontMatch() {
        PersistentRememberMeToken token = new PersistentRememberMeToken("joe", "series","wrongtoken", new Date());
        services.setTokenRepository(new MockTokenRepository(token));
        services.processAutoLoginCookie(new String[] {"series", "token"}, new MockHttpServletRequest(),
                new MockHttpServletResponse());
    }

    @Test
    public void successfulAutoLoginCreatesNewTokenAndCookieWithSameSeries() {
        MockTokenRepository repo =
                new MockTokenRepository(new PersistentRememberMeToken("joe", "series","token", new Date()));
        services.setTokenRepository(repo);
        // 12 => b64 length will be 16
        services.setTokenLength(12);
        MockHttpServletResponse response = new MockHttpServletResponse();
        services.processAutoLoginCookie(new String[] {"series", "token"}, new MockHttpServletRequest(), response);
        assertEquals("series",repo.getStoredToken().getSeries());
        assertEquals(16, repo.getStoredToken().getTokenValue().length());
        String[] cookie = services.decodeCookie(response.getCookie("mycookiename").getValue());
        assertEquals("series", cookie[0]);
        assertEquals(repo.getStoredToken().getTokenValue(), cookie[1]);
    }

    @Test
    public void loginSuccessCreatesNewTokenAndCookieWithNewSeries() {
        services.setAlwaysRemember(true);
        MockTokenRepository repo = new MockTokenRepository(null);
        services.setTokenRepository(repo);
        services.setTokenLength(12);
        services.setSeriesLength(12);
        MockHttpServletResponse response = new MockHttpServletResponse();
        services.loginSuccess(new MockHttpServletRequest(),
                response, new UsernamePasswordAuthenticationToken("joe","password"));
        assertEquals(16, repo.getStoredToken().getSeries().length());
        assertEquals(16, repo.getStoredToken().getTokenValue().length());

        String[] cookie = services.decodeCookie(response.getCookie("mycookiename").getValue());

        assertEquals(repo.getStoredToken().getSeries(), cookie[0]);
        assertEquals(repo.getStoredToken().getTokenValue(), cookie[1]);
    }

    @Test
    public void logoutClearsUsersTokenAndCookie() throws Exception {
        Cookie cookie = new Cookie("mycookiename", "somevalue");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie[] {cookie});
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockTokenRepository repo =
            new MockTokenRepository(new PersistentRememberMeToken("joe", "series","token", new Date()));
        services.setTokenRepository(repo);
        services.logout(request, response, new TestingAuthenticationToken("joe","somepass","SOME_AUTH"));
        Cookie returnedCookie = response.getCookie("mycookiename");
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    private class MockTokenRepository implements PersistentTokenRepository {
        private PersistentRememberMeToken storedToken;

        private MockTokenRepository(PersistentRememberMeToken token) {
            storedToken = token;
        }

        public void createNewToken(PersistentRememberMeToken token) {
            storedToken = token;
        }

        public void updateToken(String series, String tokenValue, Date lastUsed) {
            storedToken = new PersistentRememberMeToken(storedToken.getUsername(), storedToken.getSeries(),
                    tokenValue, lastUsed);
        }

        public PersistentRememberMeToken getTokenForSeries(String seriesId) {
            return storedToken;
        }

        public void removeUserTokens(String username) {
        }

        PersistentRememberMeToken getStoredToken() {
            return storedToken;
        }
    }
}
