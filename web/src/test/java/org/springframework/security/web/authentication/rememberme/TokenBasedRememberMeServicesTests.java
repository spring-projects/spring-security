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

import java.util.Date;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.test.web.CodecTestUtils;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices.RememberMeTokenAlgorithm;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests
 * {@link org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices}
 * .
 *
 * @author Ben Alex
 * @author Marcus Da Coregio
 */
public class TokenBasedRememberMeServicesTests {

	private UserDetailsService uds;

	private UserDetails user = new User("someone", "password", true, true, true, true,
			AuthorityUtils.createAuthorityList("ROLE_ABC"));

	private TokenBasedRememberMeServices services;

	@BeforeEach
	public void createTokenBasedRememberMeServices() {
		this.uds = mock(UserDetailsService.class);
		this.services = new TokenBasedRememberMeServices("key", this.uds);
	}

	void udsWillReturnUser() {
		given(this.uds.loadUserByUsername(any(String.class))).willReturn(this.user);
	}

	void udsWillThrowNotFound() {
		given(this.uds.loadUserByUsername(any(String.class))).willThrow(new UsernameNotFoundException(""));
	}

	void udsWillReturnNull() {
		given(this.uds.loadUserByUsername(any(String.class))).willReturn(null);
	}

	private long determineExpiryTimeFromBased64EncodedToken(String validToken) {
		String cookieAsPlainText = CodecTestUtils.decodeBase64(validToken);
		String[] cookieTokens = getCookieTokens(cookieAsPlainText);
		if (isValidCookieTokensLength(cookieTokens)) {
			try {
				return Long.parseLong(cookieTokens[1]);
			}
			catch (NumberFormatException ignored) {
			}
		}
		return -1;
	}

	private String[] getCookieTokens(String cookieAsPlainText) {
		return StringUtils.delimitedListToStringArray(cookieAsPlainText, ":");
	}

	private String determineAlgorithmNameFromBase64EncodedToken(String validToken) {
		String cookieAsPlainText = CodecTestUtils.decodeBase64(validToken);
		String[] cookieTokens = getCookieTokens(cookieAsPlainText);
		if (isValidCookieTokensLength(cookieTokens)) {
			return cookieTokens[2];
		}
		return null;
	}

	private boolean isValidCookieTokensLength(String[] cookieTokens) {
		return cookieTokens.length == 3 || cookieTokens.length == 4;
	}

	private String generateCorrectCookieContentForTokenNoAlgorithmName(long expiryTime, String username,
			String password, String key) {
		return generateCorrectCookieContentForTokenWithAlgorithmName(expiryTime, username, password, key,
				RememberMeTokenAlgorithm.MD5);
	}

	private String generateCorrectCookieContentForTokenNoAlgorithmName(long expiryTime, String username,
			String password, String key, RememberMeTokenAlgorithm algorithm) {
		// format is:
		// username + ":" + expiryTime + ":" + Md5Hex(username + ":" + expiryTime + ":" +
		// password + ":" + key)
		String signatureValue = CodecTestUtils.algorithmHex(algorithm.getDigestAlgorithm(),
				username + ":" + expiryTime + ":" + password + ":" + key);
		String tokenValue = username + ":" + expiryTime + ":" + signatureValue;
		return CodecTestUtils.encodeBase64(tokenValue);
	}

	private String generateCorrectCookieContentForTokenWithAlgorithmName(long expiryTime, String username,
			String password, String key, RememberMeTokenAlgorithm algorithm) {
		// format is:
		// username + ":" + expiryTime + ":" + algorithmName + ":" + algorithmHex(username
		// + ":" + expiryTime + ":" +
		// password + ":" + key)
		String signatureValue = CodecTestUtils.algorithmHex(algorithm.getDigestAlgorithm(),
				username + ":" + expiryTime + ":" + password + ":" + key);
		String tokenValue = username + ":" + expiryTime + ":" + algorithm.name() + ":" + signatureValue;
		return CodecTestUtils.encodeBase64(tokenValue);
	}

	@Test
	public void autoLoginReturnsNullIfNoCookiePresented() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		Authentication result = this.services.autoLogin(new MockHttpServletRequest(), response);
		assertThat(result).isNull();
		// No cookie set
		assertThat(response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY)).isNull();
	}

	@Test
	public void autoLoginIgnoresUnrelatedCookie() {
		Cookie cookie = new Cookie("unrelated_cookie", "foobar");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		Authentication result = this.services.autoLogin(request, response);
		assertThat(result).isNull();
		assertThat(response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY)).isNull();
	}

	@Test
	public void autoLoginReturnsNullForExpiredCookieAndClearsCookie() {
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				generateCorrectCookieContentForTokenNoAlgorithmName(System.currentTimeMillis() - 1000000, "someone",
						"password", "key"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		assertThat(this.services.autoLogin(request, response)).isNull();
		Cookie returnedCookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginReturnsNullAndClearsCookieIfMissingThreeTokensInCookieValue() {
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				CodecTestUtils.encodeBase64("x"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		assertThat(this.services.autoLogin(request, response)).isNull();
		Cookie returnedCookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginClearsNonBase64EncodedCookie() {
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				"NOT_BASE_64_ENCODED");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		assertThat(this.services.autoLogin(request, response)).isNull();
		Cookie returnedCookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginClearsCookieIfSignatureBlocksDoesNotMatchExpectedValue() {
		udsWillReturnUser();
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				generateCorrectCookieContentForTokenNoAlgorithmName(System.currentTimeMillis() + 1000000, "someone",
						"password", "WRONG_KEY"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		assertThat(this.services.autoLogin(request, response)).isNull();
		Cookie returnedCookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginClearsCookieIfTokenDoesNotContainANumberInCookieValue() {
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				CodecTestUtils.encodeBase64("username:NOT_A_NUMBER:signature"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		assertThat(this.services.autoLogin(request, response)).isNull();
		Cookie returnedCookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginClearsCookieIfUserNotFound() {
		udsWillThrowNotFound();
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				generateCorrectCookieContentForTokenNoAlgorithmName(System.currentTimeMillis() + 1000000, "someone",
						"password", "key"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		assertThat(this.services.autoLogin(request, response)).isNull();
		Cookie returnedCookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginClearsCookieIfUserServiceMisconfigured() {
		udsWillReturnNull();
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				generateCorrectCookieContentForTokenNoAlgorithmName(System.currentTimeMillis() + 1000000, "someone",
						"password", "key"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		assertThatIllegalArgumentException().isThrownBy(() -> this.services.autoLogin(request, response));
	}

	@Test
	public void autoLoginWithValidTokenAndUserSucceeds() {
		udsWillReturnUser();
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				generateCorrectCookieContentForTokenNoAlgorithmName(System.currentTimeMillis() + 1000000, "someone",
						"password", "key"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		Authentication result = this.services.autoLogin(request, response);
		assertThat(result).isNotNull();
		assertThat(result.getPrincipal()).isEqualTo(this.user);
	}

	@Test
	public void autoLoginWhenTokenNoAlgorithmAndDifferentMatchingAlgorithmThenReturnsNullAndClearCookie() {
		udsWillReturnUser();
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				generateCorrectCookieContentForTokenNoAlgorithmName(System.currentTimeMillis() + 1000000, "someone",
						"password", "key", RememberMeTokenAlgorithm.MD5));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services.setMatchingAlgorithm(RememberMeTokenAlgorithm.SHA256);
		Authentication result = this.services.autoLogin(request, response);
		Cookie returnedCookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(result).isNull();
		assertThat(returnedCookie).isNotNull();
		assertThat(returnedCookie.getMaxAge()).isZero();
	}

	@Test
	public void autoLoginWhenTokenNoAlgorithmAndSameMatchingAlgorithmThenSucceeds() {
		udsWillReturnUser();
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				generateCorrectCookieContentForTokenNoAlgorithmName(System.currentTimeMillis() + 1000000, "someone",
						"password", "key", RememberMeTokenAlgorithm.SHA256));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services.setMatchingAlgorithm(RememberMeTokenAlgorithm.SHA256);
		Authentication result = this.services.autoLogin(request, response);
		assertThat(result).isNotNull();
		assertThat(result.getPrincipal()).isEqualTo(this.user);
	}

	@Test
	public void autoLoginWhenTokenHasAlgorithmAndSameMatchingAlgorithmThenUsesTokenAlgorithmAndSucceeds() {
		udsWillReturnUser();
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				generateCorrectCookieContentForTokenWithAlgorithmName(System.currentTimeMillis() + 1000000, "someone",
						"password", "key", RememberMeTokenAlgorithm.SHA256));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services.setMatchingAlgorithm(RememberMeTokenAlgorithm.SHA256);
		Authentication result = this.services.autoLogin(request, response);
		assertThat(result).isNotNull();
		assertThat(result.getPrincipal()).isEqualTo(this.user);
	}

	@Test
	public void autoLoginWhenTokenHasAlgorithmAndDifferentMatchingAlgorithmThenUsesTokenAlgorithmAndSucceeds() {
		udsWillReturnUser();
		Cookie cookie = new Cookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
				generateCorrectCookieContentForTokenWithAlgorithmName(System.currentTimeMillis() + 1000000, "someone",
						"password", "key", RememberMeTokenAlgorithm.SHA256));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(cookie);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services.setMatchingAlgorithm(RememberMeTokenAlgorithm.MD5);
		Authentication result = this.services.autoLogin(request, response);
		assertThat(result).isNotNull();
		assertThat(result.getPrincipal()).isEqualTo(this.user);
	}

	@Test
	public void testGettersSetters() {
		assertThat(this.services.getUserDetailsService()).isEqualTo(this.uds);
		assertThat(this.services.getKey()).isEqualTo("key");
		assertThat(this.services.getParameter()).isEqualTo(AbstractRememberMeServices.DEFAULT_PARAMETER);
		this.services.setParameter("some_param");
		assertThat(this.services.getParameter()).isEqualTo("some_param");
		this.services.setTokenValiditySeconds(12);
		assertThat(this.services.getTokenValiditySeconds()).isEqualTo(12);
	}

	@Test
	public void loginFailClearsCookie() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services.loginFail(request, response);
		Cookie cookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(cookie).isNotNull();
		assertThat(cookie.getMaxAge()).isZero();
	}

	@Test
	public void loginSuccessIgnoredIfParameterNotSetOrFalse() {
		TokenBasedRememberMeServices services = new TokenBasedRememberMeServices("key",
				new AbstractRememberMeServicesTests.MockUserDetailsService(null, false));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(AbstractRememberMeServices.DEFAULT_PARAMETER, "false");
		MockHttpServletResponse response = new MockHttpServletResponse();
		services.loginSuccess(request, response, new TestingAuthenticationToken("someone", "password", "ROLE_ABC"));
		Cookie cookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(cookie).isNull();
	}

	@Test
	public void loginSuccessNormalWithNonUserDetailsBasedPrincipalSetsExpectedCookie() {
		// SEC-822
		this.services.setTokenValiditySeconds(500000000);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(AbstractRememberMeServices.DEFAULT_PARAMETER, "true");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services.loginSuccess(request, response,
				new TestingAuthenticationToken("someone", "password", "ROLE_ABC"));
		Cookie cookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		String expiryTime = this.services.decodeCookie(cookie.getValue())[1];
		long expectedExpiryTime = 1000L * 500000000;
		expectedExpiryTime += System.currentTimeMillis();
		assertThat(Long.parseLong(expiryTime) > expectedExpiryTime - 10000).isTrue();
		assertThat(cookie).isNotNull();
		assertThat(cookie.getMaxAge()).isEqualTo(this.services.getTokenValiditySeconds());
		assertThat(CodecTestUtils.isBase64(cookie.getValue().getBytes())).isTrue();
		assertThat(new Date().before(new Date(determineExpiryTimeFromBased64EncodedToken(cookie.getValue())))).isTrue();
	}

	@Test
	public void loginSuccessNormalWithUserDetailsBasedPrincipalSetsExpectedCookie() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(AbstractRememberMeServices.DEFAULT_PARAMETER, "true");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services.loginSuccess(request, response,
				new TestingAuthenticationToken("someone", "password", "ROLE_ABC"));
		Cookie cookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(cookie).isNotNull();
		assertThat(cookie.getMaxAge()).isEqualTo(this.services.getTokenValiditySeconds());
		assertThat(CodecTestUtils.isBase64(cookie.getValue().getBytes())).isTrue();
		assertThat(new Date().before(new Date(determineExpiryTimeFromBased64EncodedToken(cookie.getValue())))).isTrue();
	}

	@Test
	public void loginSuccessWhenDefaultEncodingAlgorithmThenContainsAlgorithmName() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(AbstractRememberMeServices.DEFAULT_PARAMETER, "true");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services.loginSuccess(request, response,
				new TestingAuthenticationToken("someone", "password", "ROLE_ABC"));
		Cookie cookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(cookie).isNotNull();
		assertThat(cookie.getMaxAge()).isEqualTo(this.services.getTokenValiditySeconds());
		assertThat(CodecTestUtils.isBase64(cookie.getValue().getBytes())).isTrue();
		assertThat(new Date().before(new Date(determineExpiryTimeFromBased64EncodedToken(cookie.getValue())))).isTrue();
		assertThat("SHA256").isEqualTo(determineAlgorithmNameFromBase64EncodedToken(cookie.getValue()));
	}

	@Test
	public void loginSuccessWhenCustomEncodingAlgorithmThenContainsAlgorithmName() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(AbstractRememberMeServices.DEFAULT_PARAMETER, "true");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services = new TokenBasedRememberMeServices("key", this.uds, RememberMeTokenAlgorithm.SHA256);
		this.services.loginSuccess(request, response,
				new TestingAuthenticationToken("someone", "password", "ROLE_ABC"));
		Cookie cookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(cookie).isNotNull();
		assertThat(cookie.getMaxAge()).isEqualTo(this.services.getTokenValiditySeconds());
		assertThat(CodecTestUtils.isBase64(cookie.getValue().getBytes())).isTrue();
		assertThat(new Date().before(new Date(determineExpiryTimeFromBased64EncodedToken(cookie.getValue())))).isTrue();
		assertThat("SHA256").isEqualTo(determineAlgorithmNameFromBase64EncodedToken(cookie.getValue()));
	}

	// SEC-933
	@Test
	public void obtainPasswordReturnsNullForTokenWithNullCredentials() {
		TestingAuthenticationToken token = new TestingAuthenticationToken("username", null);
		assertThat(this.services.retrievePassword(token)).isNull();
	}

	// SEC-949
	@Test
	public void negativeValidityPeriodIsSetOnCookieButExpiryTimeRemainsAtTwoWeeks() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(AbstractRememberMeServices.DEFAULT_PARAMETER, "true");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.services.setTokenValiditySeconds(-1);
		this.services.loginSuccess(request, response,
				new TestingAuthenticationToken("someone", "password", "ROLE_ABC"));
		Cookie cookie = response.getCookie(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
		assertThat(cookie).isNotNull();
		// Check the expiry time is within 50ms of two weeks from current time
		assertThat(determineExpiryTimeFromBased64EncodedToken(cookie.getValue())
				- System.currentTimeMillis() > AbstractRememberMeServices.TWO_WEEKS_S - 50).isTrue();
		assertThat(cookie.getMaxAge()).isEqualTo(-1);
		assertThat(CodecTestUtils.isBase64(cookie.getValue().getBytes())).isTrue();
	}

	@Test
	public void constructorWhenEncodingAlgorithmNullThenException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> new TokenBasedRememberMeServices("key", this.uds, null))
				.withMessage("encodingAlgorithm cannot be null");
	}

	@Test
	public void constructorWhenNoEncodingAlgorithmSpecifiedThenSha256() {
		TokenBasedRememberMeServices rememberMeServices = new TokenBasedRememberMeServices("key", this.uds);
		RememberMeTokenAlgorithm encodingAlgorithm = (RememberMeTokenAlgorithm) ReflectionTestUtils
				.getField(rememberMeServices, "encodingAlgorithm");
		assertThat(encodingAlgorithm).isSameAs(RememberMeTokenAlgorithm.SHA256);
	}

}
