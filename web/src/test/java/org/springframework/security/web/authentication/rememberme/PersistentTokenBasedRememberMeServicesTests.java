/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.authentication.rememberme;

import static org.assertj.core.api.Assertions.*;

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

/**
 * @author Luke Taylor
 */
public class PersistentTokenBasedRememberMeServicesTests {

	private PersistentTokenBasedRememberMeServices services;

	private MockTokenRepository repo;

	@Before
	public void setUpData() throws Exception {
		services = new PersistentTokenBasedRememberMeServices("key",
				new AbstractRememberMeServicesTests.MockUserDetailsService(AbstractRememberMeServicesTests.joe, false),
				new InMemoryTokenRepositoryImpl());
		services.setCookieName("mycookiename");
		// Default to 100 days (see SEC-1081).
		services.setTokenValiditySeconds(100 * 24 * 60 * 60);
		services.afterPropertiesSet();
	}

	@Test(expected = InvalidCookieException.class)
	public void loginIsRejectedWithWrongNumberOfCookieTokens() {
		services.processAutoLoginCookie(new String[] { "series", "token", "extra" }, new MockHttpServletRequest(),
				new MockHttpServletResponse());
	}

	@Test(expected = RememberMeAuthenticationException.class)
	public void loginIsRejectedWhenNoTokenMatchingSeriesIsFound() {
		services = create(null);
		services.processAutoLoginCookie(new String[] { "series", "token" }, new MockHttpServletRequest(),
				new MockHttpServletResponse());
	}

	@Test(expected = RememberMeAuthenticationException.class)
	public void loginIsRejectedWhenTokenIsExpired() {
		services = create(new PersistentRememberMeToken("joe", "series", "token",
				new Date(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(1) - 100)));
		services.setTokenValiditySeconds(1);

		services.processAutoLoginCookie(new String[] { "series", "token" }, new MockHttpServletRequest(),
				new MockHttpServletResponse());
	}

	@Test(expected = CookieTheftException.class)
	public void cookieTheftIsDetectedWhenSeriesAndTokenDontMatch() {
		services = create(new PersistentRememberMeToken("joe", "series", "wrongtoken", new Date()));
		services.processAutoLoginCookie(new String[] { "series", "token" }, new MockHttpServletRequest(),
				new MockHttpServletResponse());
	}

	@Test
	public void successfulAutoLoginCreatesNewTokenAndCookieWithSameSeries() {
		services = create(new PersistentRememberMeToken("joe", "series", "token", new Date()));
		// 12 => b64 length will be 16
		services.setTokenLength(12);
		MockHttpServletResponse response = new MockHttpServletResponse();
		services.processAutoLoginCookie(new String[] { "series", "token" }, new MockHttpServletRequest(), response);
		assertThat(repo.getStoredToken().getSeries()).isEqualTo("series");
		assertThat(repo.getStoredToken().getTokenValue().length()).isEqualTo(16);
		String[] cookie = services.decodeCookie(response.getCookie("mycookiename").getValue());
		assertThat(cookie[0]).isEqualTo("series");
		assertThat(cookie[1]).isEqualTo(repo.getStoredToken().getTokenValue());
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
		assertThat(repo.getStoredToken().getSeries().length()).isEqualTo(16);
		assertThat(repo.getStoredToken().getTokenValue().length()).isEqualTo(16);

		String[] cookie = services.decodeCookie(response.getCookie("mycookiename").getValue());

		assertThat(cookie[0]).isEqualTo(repo.getStoredToken().getSeries());
		assertThat(cookie[1]).isEqualTo(repo.getStoredToken().getTokenValue());
	}

	@Test
	public void logoutClearsUsersTokenAndCookie() {
		Cookie cookie = new Cookie("mycookiename", "somevalue");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		services = create(new PersistentRememberMeToken("joe", "series", "token", new Date()));
		services.logout(request, response, new TestingAuthenticationToken("joe", "somepass", "SOME_AUTH"));
		Cookie returnedCookie = response.getCookie("mycookiename");
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();

		// SEC-1280
		services.logout(request, response, null);
	}

	private PersistentTokenBasedRememberMeServices create(PersistentRememberMeToken token) {
		repo = new MockTokenRepository(token);
		PersistentTokenBasedRememberMeServices services = new PersistentTokenBasedRememberMeServices("key",
				new AbstractRememberMeServicesTests.MockUserDetailsService(AbstractRememberMeServicesTests.joe, false),
				repo);

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
			storedToken = new PersistentRememberMeToken(storedToken.getUsername(), storedToken.getSeries(), tokenValue,
					lastUsed);
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
