package org.springframework.security.ui.rememberme;

import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import java.util.Date;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class PersistentTokenBasedRememberMeServicesTests {
    private PersistentTokenBasedRememberMeServices services;

    @Before
    public void setUpData() throws Exception {
        services = new PersistentTokenBasedRememberMeServices();
    }

    @Test(expected = InvalidCookieException.class)
    public void loginIsRejectedWithWrongNumberOfCookieTokens() {
        services.setCookieName("mycookiename");
        services.processAutoLoginCookie(new String[] {"series", "token", "extra"}, new MockHttpServletRequest(), 
                new MockHttpServletResponse());
    }

    @Test(expected = RememberMeAuthenticationException.class)
    public void loginIsRejectedWhenNoTokenMatchingSeriesIsFound() {
        services.setCookieName("mycookiename");
        services.setTokenRepository(new MockTokenRepository(null));
        services.processAutoLoginCookie(new String[] {"series", "token"}, new MockHttpServletRequest(),
                new MockHttpServletResponse());
    }

    @Test(expected = CookieTheftException.class)
    public void cookieTheftIsDetectedWhenSeriesAndTokenDontMatch() {
        services.setCookieName("mycookiename");
        PersistentRememberMeToken token = new PersistentRememberMeToken("joe", "series","wrongtoken", new Date());
        services.setTokenRepository(new MockTokenRepository(token));
        services.processAutoLoginCookie(new String[] {"series", "token"}, new MockHttpServletRequest(),
                new MockHttpServletResponse());
    }

    @Test
    public void successfulAutoLoginCreatesNewTokenAndCookieWithSameSeries() {
        services.setCookieName("mycookiename");
        MockTokenRepository repo =
                new MockTokenRepository(new PersistentRememberMeToken("joe", "series","token", new Date()));
        services.setTokenRepository(repo);
        // 12 => b64 length will be 16
        services.setTokenLength(12);
        services.processAutoLoginCookie(new String[] {"series", "token"}, new MockHttpServletRequest(),
                new MockHttpServletResponse());
        assertEquals("series",repo.getStoredToken().getSeries());
        assertEquals(16, repo.getStoredToken().getTokenValue().length());
    }

    @Test
    public void loginSuccessCreatesNewTokenAndCookieWithNewSeries() {
        services.setAlwaysRemember(true);
        MockTokenRepository repo = new MockTokenRepository(null);
        services.setTokenRepository(repo);
        services.setTokenLength(12);
        services.setSeriesLength(12);
        services.loginSuccess(new MockHttpServletRequest(),
                new MockHttpServletResponse(), new UsernamePasswordAuthenticationToken("joe","password"));
        assertEquals(16, repo.getStoredToken().getSeries().length());
        assertEquals(16, repo.getStoredToken().getTokenValue().length());
    }



    private class MockTokenRepository implements PersistentTokenRepository {
        private PersistentRememberMeToken storedToken;

        private MockTokenRepository(PersistentRememberMeToken token) {
            storedToken = token;
        }

        public void saveToken(PersistentRememberMeToken token) {
            storedToken = token;
        }

        public PersistentRememberMeToken getTokenForSeries(String seriesId) {
            return storedToken;
        }

        public void removeAllTokens(String username) {
        }

        PersistentRememberMeToken getStoredToken() {
            return storedToken;
        }
    }
}
