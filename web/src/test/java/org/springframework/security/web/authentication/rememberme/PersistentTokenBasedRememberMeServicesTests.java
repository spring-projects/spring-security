package org.springframework.security.web.authentication.rememberme;

import static org.junit.Assert.*;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.Cookie;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.rememberme.CookieTheftException;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServicesTests.*;

/**
 * @author Luke Taylor
 */
public class PersistentTokenBasedRememberMeServicesTests {
	private PersistentTokenBasedRememberMeServices services;

	private MockTokenRepository repo;

	@Before
	public void setUpData() throws Exception {
		services = new PersistentTokenBasedRememberMeServices("key",
				new AbstractRememberMeServicesTests.MockUserDetailsService(
						AbstractRememberMeServicesTests.joe, false),
				new InMemoryTokenRepositoryImpl());
		services.setCookieName("mycookiename");
		// Default to 100 days (see SEC-1081).
		services.setTokenValiditySeconds(100 * 24 * 60 * 60);
		services.afterPropertiesSet();
	}

	@Test(expected = InvalidCookieException.class)
	public void loginIsRejectedWithWrongNumberOfCookieTokens() {
		services.processAutoLoginCookie(new String[] { "series", "token", "extra" },
				new MockHttpServletRequest(), new MockHttpServletResponse());
	}

	@Test(expected = RememberMeAuthenticationException.class)
	public void loginIsRejectedWhenNoTokenMatchingSeriesIsFound() {
		services = create(null);
		services.processAutoLoginCookie(new String[] { "series", "token" },
				new MockHttpServletRequest(), new MockHttpServletResponse());
	}

	@Test(expected = RememberMeAuthenticationException.class)
	public void loginIsRejectedWhenTokenIsExpired() {
		services = create(new PersistentRememberMeToken("joe", "series", "token",
				new Date(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(1) - 100)));
		services.setTokenValiditySeconds(1);

		services.processAutoLoginCookie(new String[] { "series", "token" },
				new MockHttpServletRequest(), new MockHttpServletResponse());
	}

	@Test(expected = CookieTheftException.class)
	public void cookieTheftIsDetectedWhenSeriesAndTokenDontMatch() {
		services = create(new PersistentRememberMeToken("joe", "series", "wrongtoken",
				new Date()));
		services.processAutoLoginCookie(new String[] { "series", "token" },
				new MockHttpServletRequest(), new MockHttpServletResponse());
	}

	@Test
	public void successfulAutoLoginCreatesNewTokenAndCookieWithSameSeries() {
		services = create(new PersistentRememberMeToken("joe", "series", "token",
				new Date()));
		// 12 => b64 length will be 16
		services.setTokenLength(12);
		MockHttpServletResponse response = new MockHttpServletResponse();
		services.processAutoLoginCookie(new String[] { "series", "token" },
				new MockHttpServletRequest(), response);
		assertEquals("series", repo.getStoredToken().getSeries());
		assertEquals(16, repo.getStoredToken().getTokenValue().length());
		String[] cookie = services.decodeCookie(response.getCookie("mycookiename")
				.getValue());
		assertEquals("series", cookie[0]);
		assertEquals(repo.getStoredToken().getTokenValue(), cookie[1]);
	}

	@Test
	public void loginSuccessCreatesNewTokenAndCookieWithNewSeries() {
		services = create(null);
		services.setAlwaysRemember(true);
		services.setTokenLength(12);
		services.setSeriesLength(12);
		MockHttpServletResponse response = new MockHttpServletResponse();
		services.loginSuccess(new MockHttpServletRequest(), response,
				new UsernamePasswordAuthenticationToken("joe", "password"));
		assertEquals(16, repo.getStoredToken().getSeries().length());
		assertEquals(16, repo.getStoredToken().getTokenValue().length());

		String[] cookie = services.decodeCookie(response.getCookie("mycookiename")
				.getValue());

		assertEquals(repo.getStoredToken().getSeries(), cookie[0]);
		assertEquals(repo.getStoredToken().getTokenValue(), cookie[1]);
	}

	@Test
	public void logoutClearsUsersTokenAndCookie() throws Exception {
		Cookie cookie = new Cookie("mycookiename", "somevalue");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		services = create(new PersistentRememberMeToken("joe", "series", "token",
				new Date()));
		services.logout(request, response, new TestingAuthenticationToken("joe",
				"somepass", "SOME_AUTH"));
		Cookie returnedCookie = response.getCookie("mycookiename");
		assertNotNull(returnedCookie);
		assertEquals(0, returnedCookie.getMaxAge());

		// SEC-1280
		services.logout(request, response, null);
	}

	private PersistentTokenBasedRememberMeServices create(PersistentRememberMeToken token) {
		repo = new MockTokenRepository(token);
		PersistentTokenBasedRememberMeServices services = new PersistentTokenBasedRememberMeServices(
				"key", new AbstractRememberMeServicesTests.MockUserDetailsService(
						AbstractRememberMeServicesTests.joe, false), repo);

		services.setCookieName("mycookiename");
		return services;
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
			storedToken = new PersistentRememberMeToken(storedToken.getUsername(),
					storedToken.getSeries(), tokenValue, lastUsed);
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
