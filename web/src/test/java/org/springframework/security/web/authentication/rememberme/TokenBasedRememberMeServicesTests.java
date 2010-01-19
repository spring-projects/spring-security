/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.rememberme;

import static org.junit.Assert.*;
import static org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices.*;

import java.util.Date;

import javax.servlet.http.Cookie;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
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
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.util.StringUtils;

/**
 * Tests {@link org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices}.
 *
 * @author Ben Alex
 */
public class TokenBasedRememberMeServicesTests {
    private Mockery jmock = new JUnit4Mockery();
    private UserDetailsService uds;
    private UserDetails user = new User("someone", "password", true, true, true, true,
            AuthorityUtils.createAuthorityList("ROLE_ABC"));
    private TokenBasedRememberMeServices services;
    private Expectations udsWillReturnUser;
    private Expectations udsWillThrowNotFound;

    //~ Methods ========================================================================================================

    @Before
    public void createTokenBasedRememberMeServices() {
        services = new TokenBasedRememberMeServices();
        uds = jmock.mock(UserDetailsService.class);
        services.setKey("key");
        services.setUserDetailsService(uds);
        udsWillReturnUser = new Expectations() {{
            oneOf(uds).loadUserByUsername(with(aNonNull(String.class))); will(returnValue(user));
        }};
        udsWillThrowNotFound = new Expectations() {{
            oneOf(uds).loadUserByUsername(with(aNonNull(String.class)));
            will(throwException(new UsernameNotFoundException("")));
        }};

    }

    private long determineExpiryTimeFromBased64EncodedToken(String validToken) {
        String cookieAsPlainText = new String(Base64.decodeBase64(validToken.getBytes()));
        String[] cookieTokens = StringUtils.delimitedListToStringArray(cookieAsPlainText, ":");

        if (cookieTokens.length == 3) {
            try {
                return new Long(cookieTokens[1]).longValue();
            } catch (NumberFormatException nfe) {}
        }

        return -1;
    }

    private String generateCorrectCookieContentForToken(long expiryTime, String username, String password, String key) {
        // format is:
        //     username + ":" + expiryTime + ":" + Md5Hex(username + ":" + expiryTime + ":" + password + ":" + key)
        String signatureValue = new String(DigestUtils.md5Hex(username + ":" + expiryTime + ":" + password + ":" + key));
        String tokenValue = username + ":" + expiryTime + ":" + signatureValue;
        String tokenValueBase64 = new String(Base64.encodeBase64(tokenValue.getBytes()));

        return tokenValueBase64;
    }

    @Test
    public void autoLoginReturnsNullIfNoCookiePresented() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(new MockHttpServletRequest(), response);
        assertNull(result);
        // No cookie set
        assertNull(response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY));
    }

    @Test
    public void autoLoginIgnoresUnrelatedCookie() throws Exception {
        Cookie cookie = new Cookie("unrelated_cookie", "foobar");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie[] {cookie});
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);
        assertNull(response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY));
    }

    @Test
    public void autoLoginReturnsNullForExpiredCookieAndClearsCookie() throws Exception {
        Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
                generateCorrectCookieContentForToken(System.currentTimeMillis() - 1000000, "someone", "password", "key"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie[] {cookie});

        MockHttpServletResponse response = new MockHttpServletResponse();

        assertNull(services.autoLogin(request, response));
        Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    @Test
    public void autoLoginReturnsNullAndClearsCookieIfMissingThreeTokensInCookieValue() throws Exception {
        Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
                new String(Base64.encodeBase64("x".getBytes())));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie[] {cookie});

        MockHttpServletResponse response = new MockHttpServletResponse();
        assertNull(services.autoLogin(request, response));

        Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    @Test
    public void autoLoginClearsNonBase64EncodedCookie() throws Exception {
        Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
                "NOT_BASE_64_ENCODED");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie[] {cookie});

        MockHttpServletResponse response = new MockHttpServletResponse();
        assertNull(services.autoLogin(request, response));

        Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    @Test
    public void autoLoginClearsCookieIfSignatureBlocksDoesNotMatchExpectedValue() throws Exception {
        jmock.checking(udsWillReturnUser);
        Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
                generateCorrectCookieContentForToken(System.currentTimeMillis() + 1000000, "someone", "password",
                    "WRONG_KEY"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie[] {cookie});

        MockHttpServletResponse response = new MockHttpServletResponse();

        assertNull(services.autoLogin(request, response));

        Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    @Test
    public void autoLoginClearsCookieIfTokenDoesNotContainANumberInCookieValue() throws Exception {
        Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
                new String(Base64.encodeBase64("username:NOT_A_NUMBER:signature".getBytes())));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie[] {cookie});

        MockHttpServletResponse response = new MockHttpServletResponse();
        assertNull(services.autoLogin(request, response));

        Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    @Test
    public void autoLoginClearsCookieIfUserNotFound() throws Exception {
        jmock.checking(udsWillThrowNotFound);
        Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
                generateCorrectCookieContentForToken(System.currentTimeMillis() + 1000000, "someone", "password", "key"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie[] {cookie});

        MockHttpServletResponse response = new MockHttpServletResponse();

        assertNull(services.autoLogin(request, response));

        Cookie returnedCookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    @Test
    public void autoLoginWithValidTokenAndUserSucceeds() throws Exception {
        jmock.checking(udsWillReturnUser);
        Cookie cookie = new Cookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY,
                generateCorrectCookieContentForToken(System.currentTimeMillis() + 1000000, "someone", "password", "key"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie[] {cookie});

        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNotNull(result);
        assertEquals(user, result.getPrincipal());
    }

    @Test
    public void testGettersSetters() {
        assertEquals(uds, services.getUserDetailsService());

        services.setKey("d");
        assertEquals("d", services.getKey());

        assertEquals(DEFAULT_PARAMETER, services.getParameter());
        services.setParameter("some_param");
        assertEquals("some_param", services.getParameter());

        services.setTokenValiditySeconds(12);
        assertEquals(12, services.getTokenValiditySeconds());
    }

    @Test
    public void loginFailClearsCookie() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        services.loginFail(request, response);

        Cookie cookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(cookie);
        assertEquals(0, cookie.getMaxAge());
    }

    @Test
    public void loginSuccessIgnoredIfParameterNotSetOrFalse() {
        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(DEFAULT_PARAMETER, "false");

        MockHttpServletResponse response = new MockHttpServletResponse();
        services.loginSuccess(request, response, new TestingAuthenticationToken("someone", "password","ROLE_ABC"));

        Cookie cookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        assertNull(cookie);
    }

    @Test
    public void loginSuccessNormalWithNonUserDetailsBasedPrincipalSetsExpectedCookie() {
        // SEC-822
        services.setTokenValiditySeconds(500000000);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(TokenBasedRememberMeServices.DEFAULT_PARAMETER, "true");

        MockHttpServletResponse response = new MockHttpServletResponse();
        services.loginSuccess(request, response, new TestingAuthenticationToken("someone", "password","ROLE_ABC"));

        Cookie cookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        String expiryTime = services.decodeCookie(cookie.getValue())[1];
        long expectedExpiryTime = 1000L * 500000000;
        expectedExpiryTime += System.currentTimeMillis();
        assertTrue(Long.parseLong(expiryTime) > expectedExpiryTime - 10000);
        assertNotNull(cookie);
        assertEquals(services.getTokenValiditySeconds(), cookie.getMaxAge());
        assertTrue(Base64.isArrayByteBase64(cookie.getValue().getBytes()));
        assertTrue(new Date().before(new Date(determineExpiryTimeFromBased64EncodedToken(cookie.getValue()))));
    }

    @Test
    public void loginSuccessNormalWithUserDetailsBasedPrincipalSetsExpectedCookie() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(TokenBasedRememberMeServices.DEFAULT_PARAMETER, "true");

        MockHttpServletResponse response = new MockHttpServletResponse();
        services.loginSuccess(request, response, new TestingAuthenticationToken("someone", "password","ROLE_ABC"));

        Cookie cookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(cookie);
        assertEquals(services.getTokenValiditySeconds(), cookie.getMaxAge());
        assertTrue(Base64.isArrayByteBase64(cookie.getValue().getBytes()));
        assertTrue(new Date().before(new Date(determineExpiryTimeFromBased64EncodedToken(cookie.getValue()))));
    }

    // SEC-933
    @Test
    public void obtainPasswordReturnsNullForTokenWithNullCredentials() throws Exception {
        TestingAuthenticationToken token = new TestingAuthenticationToken("username", null);
        assertNull(services.retrievePassword(token));
    }

    // SEC-949
    @Test
    public void negativeValidityPeriodIsSetOnCookieButExpiryTimeRemainsAtTwoWeeks() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter(DEFAULT_PARAMETER, "true");

        MockHttpServletResponse response = new MockHttpServletResponse();
        services.setTokenValiditySeconds(-1);
        services.loginSuccess(request, response, new TestingAuthenticationToken("someone", "password","ROLE_ABC"));

        Cookie cookie = response.getCookie(SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(cookie);
        // Check the expiry time is within 50ms of two weeks from current time
        assertTrue(determineExpiryTimeFromBased64EncodedToken(cookie.getValue()) - System.currentTimeMillis() >
                TWO_WEEKS_S - 50);
        assertEquals(-1, cookie.getMaxAge());
        assertTrue(Base64.isArrayByteBase64(cookie.getValue().getBytes()));
    }
}
