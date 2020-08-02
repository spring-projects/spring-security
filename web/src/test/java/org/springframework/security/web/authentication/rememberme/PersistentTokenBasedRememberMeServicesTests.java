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

import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.Cookie;

import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 */
public class PersistentTokenBasedRememberMeServicesTests {

	private PersistentTokenBasedRememberMeServices services;

	private MockTokenRepository repo;

	@Before
	public void setUpData() throws Exception {
		this.services = new PersistentTokenBasedRememberMeServices("key",
				new AbstractRememberMeServicesTests.MockUserDetailsService(AbstractRememberMeServicesTests.joe, false),
				new InMemoryTokenRepositoryImpl());
		this.services.setCookieName("mycookiename");
		// Default to 100 days (see SEC-1081).
		this.services.setTokenValiditySeconds(100 * 24 * 60 * 60);
		this.services.afterPropertiesSet();
	}

	@Test(expected = InvalidCookieException.class)
	public void loginIsRejectedWithWrongNumberOfCookieTokens() {
		this.services.processAutoLoginCookie(new String[] { "series", "token", "extra" }, new MockHttpServletRequest(),
				new MockHttpServletResponse());
	}

	@Test(expected = RememberMeAuthenticationException.class)
	public void loginIsRejectedWhenNoTokenMatchingSeriesIsFound() {
		this.services = create(null);
		this.services.processAutoLoginCookie(new String[] { "series", "token" }, new MockHttpServletRequest(),
				new MockHttpServletResponse());
	}

	@Test(expected = RememberMeAuthenticationException.class)
	public void loginIsRejectedWhenTokenIsExpired() {
		this.services = create(new PersistentRememberMeToken("joe", "series", "token",
				new Date(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(1) - 100)));
		this.services.setTokenValiditySeconds(1);
		this.services.processAutoLoginCookie(new String[] { "series", "token" }, new MockHttpServletRequest(),
				new MockHttpServletResponse());
	}

	@Test(expected = CookieTheftException.class)
	public void cookieTheftIsDetectedWhenSeriesAndTokenDontMatch() {
		this.services = create(new PersistentRememberMeToken("joe", "series", "wrongtoken", new Date()));
		this.services.processAutoLoginCookie(new String[] { "series", "token" }, new MockHttpServletRequest(),
				new MockHttpServletResponse());
	}

	@Test
	public void successfulAutoLoginCreatesNewTokenAndCookieWithSameSeries() {
		this.services = create(new PersistentRememberMeToken("joe", "series", "token", new Date()));
		// 12 => b64 length will be 16
		this.services.setTokenLength(12);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services.processAutoLoginCookie(new String[] { "series", "token" }, new MockHttpServletRequest(),
				response);
		assertThat(this.repo.getStoredToken().getSeries()).isEqualTo("series");
		assertThat(this.repo.getStoredToken().getTokenValue().length()).isEqualTo(16);
		String[] cookie = this.services.decodeCookie(response.getCookie("mycookiename").getValue());
		assertThat(cookie[0]).isEqualTo("series");
		assertThat(cookie[1]).isEqualTo(this.repo.getStoredToken().getTokenValue());
	}

	@Test
	public void loginSuccessCreatesNewTokenAndCookieWithNewSeries() {
		this.services = create(null);
		this.services.setAlwaysRemember(true);
		this.services.setTokenLength(12);
		this.services.setSeriesLength(12);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services.loginSuccess(new MockHttpServletRequest(), response,
				new UsernamePasswordAuthenticationToken("joe", "password"));
		assertThat(this.repo.getStoredToken().getSeries().length()).isEqualTo(16);
		assertThat(this.repo.getStoredToken().getTokenValue().length()).isEqualTo(16);
		String[] cookie = this.services.decodeCookie(response.getCookie("mycookiename").getValue());
		assertThat(cookie[0]).isEqualTo(this.repo.getStoredToken().getSeries());
		assertThat(cookie[1]).isEqualTo(this.repo.getStoredToken().getTokenValue());
	}

	@Test
	public void logoutClearsUsersTokenAndCookie() {
		Cookie cookie = new Cookie("mycookiename", "somevalue");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services = create(new PersistentRememberMeToken("joe", "series", "token", new Date()));
		this.services.logout(request, response, new TestingAuthenticationToken("joe", "somepass", "SOME_AUTH"));
		Cookie returnedCookie = response.getCookie("mycookiename");
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
		// SEC-1280
		this.services.logout(request, response, null);
	}

	private PersistentTokenBasedRememberMeServices create(PersistentRememberMeToken token) {
		this.repo = new MockTokenRepository(token);
		PersistentTokenBasedRememberMeServices services = new PersistentTokenBasedRememberMeServices("key",
				new AbstractRememberMeServicesTests.MockUserDetailsService(AbstractRememberMeServicesTests.joe, false),
				this.repo);
		services.setCookieName("mycookiename");
		return services;
	}

	private final class MockTokenRepository implements PersistentTokenRepository {

		private PersistentRememberMeToken storedToken;

		private MockTokenRepository(PersistentRememberMeToken token) {
			this.storedToken = token;
		}

		@Override
		public void createNewToken(PersistentRememberMeToken token) {
			this.storedToken = token;
		}

		@Override
		public void updateToken(String series, String tokenValue, Date lastUsed) {
			this.storedToken = new PersistentRememberMeToken(this.storedToken.getUsername(),
					this.storedToken.getSeries(), tokenValue, lastUsed);
		}

		@Override
		public PersistentRememberMeToken getTokenForSeries(String seriesId) {
			return this.storedToken;
		}

		@Override
		public void removeUserTokens(String username) {
		}

		PersistentRememberMeToken getStoredToken() {
			return this.storedToken;
		}

	}

}
