/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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
import static org.mockito.Mockito.*;
import static org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices.*;

import java.util.*;
import javax.servlet.http.Cookie;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;

/**
 * Tests
 * {@link org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices}
 * .
 *
 * @author Ben Alex
 */
public class TokenBasedRememberMeServicesTests {

	private UserDetailsService uds;

	private UserDetails user = new User("someone", "password", true, true, true, true,
			AuthorityUtils.createAuthorityList("ROLE_ABC"));

	private TokenBasedRememberMeServices services;

	@Before
	public void createTokenBasedRememberMeServices() {
		uds = mock(UserDetailsService.class);
		services = new TokenBasedRememberMeServices("key", uds);
	}

	void udsWillReturnUser() {
		when(uds.loadUserByUsername(any(String.class))).thenReturn(user);
	}

	void udsWillThrowNotFound() {
		when(uds.loadUserByUsername(any(String.class))).thenThrow(new UsernameNotFoundException(""));
	}

	void udsWillReturnNull() {
		when(uds.loadUserByUsername(any(String.class))).thenReturn(null);
	}

	private long determineExpiryTimeFromBased64EncodedToken(String validToken) {
		String cookieAsPlainText = new String(Base64.decodeBase64(validToken.getBytes()));
		String[] cookieTokens = StringUtils.delimitedListToStringArray(cookieAsPlainText, ":");

		if (cookieTokens.length == 3) {
			try {
				return Long.parseLong(cookieTokens[1]);
			}
			catch (NumberFormatException ignored) {
			}
		}

		return -1;
	}

	private String generateCorrectCookieContentForToken(long expiryTime, String username, String password, String key) {
		// format is:
		// username + ":" + expiryTime + ":" + Md5Hex(username + ":" + expiryTime + ":" +
		// password + ":" + key)
		String signatureValue = DigestUtils.md5Hex(username + ":" + expiryTime + ":" + password + ":" + key);
		String tokenValue = username + ":" + expiryTime + ":" + signatureValue;

		return new String(Base64.encodeBase64(tokenValue.getBytes()));
	}

	@Test
	public void autoLoginReturnsNullIfNoCookiePresented() {
		MockHttpServletResponse response = new MockHttpServletResponse();

		Authentication result = services.autoLogin(new MockHttpServletRequest(), response);
		assertThat(result).isNull();
		// No cookie set
		assertThat(response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY)).isNull();
	}

	@Test
	public void autoLoginIgnoresUnrelatedCookie() {
		Cookie cookie = new Cookie("unrelated_cookie", "foobar");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();

		Authentication result = services.autoLogin(request, response);

		assertThat(result).isNull();
		assertThat(response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY)).isNull();
	}

	@Test
	public void autoLoginReturnsNullForExpiredCookieAndClearsCookie() {
		Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, generateCorrectCookieContentForToken(
				System.currentTimeMillis() - 1000000, "someone", "password", "key"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);

		MockHttpServletResponse response = new MockHttpServletResponse();

		assertThat(services.autoLogin(request, response)).isNull();
		Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginReturnsNullAndClearsCookieIfMissingThreeTokensInCookieValue() {
		Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				new String(Base64.encodeBase64("x".getBytes())));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);

		MockHttpServletResponse response = new MockHttpServletResponse();
		assertThat(services.autoLogin(request, response)).isNull();

		Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginClearsNonBase64EncodedCookie() {
		Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, "NOT_BASE_64_ENCODED");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);

		MockHttpServletResponse response = new MockHttpServletResponse();
		assertThat(services.autoLogin(request, response)).isNull();

		Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginClearsCookieIfSignatureBlocksDoesNotMatchExpectedValue() {
		udsWillReturnUser();
		Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, generateCorrectCookieContentForToken(
				System.currentTimeMillis() + 1000000, "someone", "password", "WRONG_KEY"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);

		MockHttpServletResponse response = new MockHttpServletResponse();

		assertThat(services.autoLogin(request, response)).isNull();

		Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginClearsCookieIfTokenDoesNotContainANumberInCookieValue() {
		Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				new String(Base64.encodeBase64("username:NOT_A_NUMBER:signature".getBytes())));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);

		MockHttpServletResponse response = new MockHttpServletResponse();
		assertThat(services.autoLogin(request, response)).isNull();

		Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginClearsCookieIfUserNotFound() {
		udsWillThrowNotFound();
		Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, generateCorrectCookieContentForToken(
				System.currentTimeMillis() + 1000000, "someone", "password", "key"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);

		MockHttpServletResponse response = new MockHttpServletResponse();

		assertThat(services.autoLogin(request, response)).isNull();

		Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test(expected = IllegalArgumentException.class)
	public void autoLoginClearsCookieIfUserServiceMisconfigured() {
		udsWillReturnNull();
		Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, generateCorrectCookieContentForToken(
				System.currentTimeMillis() + 1000000, "someone", "password", "key"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);

		MockHttpServletResponse response = new MockHttpServletResponse();

		services.autoLogin(request, response);
	}

	@Test
	public void autoLoginWithValidTokenAndUserSucceeds() {
		udsWillReturnUser();
		Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, generateCorrectCookieContentForToken(
				System.currentTimeMillis() + 1000000, "someone", "password", "key"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);

		MockHttpServletResponse response = new MockHttpServletResponse();

		Authentication result = services.autoLogin(request, response);

		assertThat(result).isNotNull();
		assertThat(result.getPrincipal()).isEqualTo(user);
	}

	@Test
	public void testGettersSetters() {
		assertThat(services.getUserDetailsService()).isEqualTo(uds);

		assertThat(services.getKey()).isEqualTo("key");

		assertThat(services.getParameter()).isEqualTo(DEFAULT_PARAMETER);
		services.setParameter("some_param");
		assertThat(services.getParameter()).isEqualTo("some_param");

		services.setTokenValiditySeconds(12);
		assertThat(services.getTokenValiditySeconds()).isEqualTo(12);
	}

	@Test
	public void loginFailClearsCookie() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		services.loginFail(request, response);

		Cookie cookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(cookie).isNotNull();
		assertThat(cookie.getMaxAge()).isZero();
	}

	@Test
	public void loginSuccessIgnoredIfParameterNotSetOrFalse() {
		TokenBasedRememberMeServices services = new TokenBasedRememberMeServices("key",
				new AbstractRememberMeServicesTests.MockUserDetailsService(null, false));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(DEFAULT_PARAMETER, "false");

		MockHttpServletResponse response = new MockHttpServletResponse();
		services.loginSuccess(request, response, new TestingAuthenticationToken("someone", "password", "ROLE_ABC"));

		Cookie cookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(cookie).isNull();
	}

	@Test
	public void loginSuccessNormalWithNonUserDetailsBasedPrincipalSetsExpectedCookie() {
		// SEC-822
		services.setTokenValiditySeconds(500000000);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(TokenBasedRememberMeServices.DEFAULT_PARAMETER, "true");

		MockHttpServletResponse response = new MockHttpServletResponse();
		services.loginSuccess(request, response, new TestingAuthenticationToken("someone", "password", "ROLE_ABC"));

		Cookie cookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		String expiryTime = services.decodeCookie(cookie.getValue())[1];
		long expectedExpiryTime = 1000L * 500000000;
		expectedExpiryTime += System.currentTimeMillis();
		assertThat(Long.parseLong(expiryTime) > expectedExpiryTime - 10000).isTrue();
		assertThat(cookie).isNotNull();
		assertThat(cookie.getMaxAge()).isEqualTo(services.getTokenValiditySeconds());
		assertThat(Base64.isArrayByteBase64(cookie.getValue().getBytes())).isTrue();
		assertThat(new Date().before(new Date(determineExpiryTimeFromBased64EncodedToken(cookie.getValue())))).isTrue();
	}

	@Test
	public void loginSuccessNormalWithUserDetailsBasedPrincipalSetsExpectedCookie() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(TokenBasedRememberMeServices.DEFAULT_PARAMETER, "true");

		MockHttpServletResponse response = new MockHttpServletResponse();
		services.loginSuccess(request, response, new TestingAuthenticationToken("someone", "password", "ROLE_ABC"));

		Cookie cookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(cookie).isNotNull();
		assertThat(cookie.getMaxAge()).isEqualTo(services.getTokenValiditySeconds());
		assertThat(Base64.isArrayByteBase64(cookie.getValue().getBytes())).isTrue();
		assertThat(new Date().before(new Date(determineExpiryTimeFromBased64EncodedToken(cookie.getValue())))).isTrue();
	}

	// SEC-933
	@Test
	public void obtainPasswordReturnsNullForTokenWithNullCredentials() {
		TestingAuthenticationToken token = new TestingAuthenticationToken("username", null);
		assertThat(services.retrievePassword(token)).isNull();
	}

	// SEC-949
	@Test
	public void negativeValidityPeriodIsSetOnCookieButExpiryTimeRemainsAtTwoWeeks() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(DEFAULT_PARAMETER, "true");

		MockHttpServletResponse response = new MockHttpServletResponse();
		services.setTokenValiditySeconds(-1);
		services.loginSuccess(request, response, new TestingAuthenticationToken("someone", "password", "ROLE_ABC"));

		Cookie cookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(cookie).isNotNull();
		// Check the expiry time is within 50ms of two weeks from current time
		assertThat(determineExpiryTimeFromBased64EncodedToken(cookie.getValue())
				- System.currentTimeMillis() > TWO_WEEKS_S - 50).isTrue();
		assertThat(cookie.getMaxAge()).isEqualTo(-1);
		assertThat(Base64.isArrayByteBase64(cookie.getValue().getBytes())).isTrue();
	}

}
