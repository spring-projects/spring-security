/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.ui.rememberme;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;
import net.sf.acegisecurity.providers.dao.AuthenticationDao;
import net.sf.acegisecurity.providers.dao.User;
import net.sf.acegisecurity.providers.dao.UsernameNotFoundException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import org.springframework.dao.DataAccessException;

import org.springframework.util.StringUtils;

import java.util.Date;

import javax.servlet.http.Cookie;


/**
 * Tests {@link
 * net.sf.acegisecurity.ui.rememberme.TokenBasedRememberMeServices}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class TokenBasedRememberMeServicesTests extends TestCase {
    //~ Constructors ===========================================================

    public TokenBasedRememberMeServicesTests() {
        super();
    }

    public TokenBasedRememberMeServicesTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(TokenBasedRememberMeServicesTests.class);
    }

    public void testAutoLoginIfDoesNotPresentAnyCookies()
        throws Exception {
        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        services.setKey("key");
        services.setAuthenticationDao(new MockAuthenticationDao(null, true));
        services.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest("dc");
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);

        Cookie returnedCookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNull(returnedCookie); // shouldn't try to invalidate our cookie
    }

    public void testAutoLoginIfDoesNotPresentRequiredCookie()
        throws Exception {
        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        services.setKey("key");
        services.setAuthenticationDao(new MockAuthenticationDao(null, true));
        services.afterPropertiesSet();

        Cookie cookie = new Cookie("unrelated_cookie", "foobar");
        MockHttpServletRequest request = new MockHttpServletRequest(null, null,
                "null", new Cookie[] {cookie});
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);

        Cookie returnedCookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNull(returnedCookie); // shouldn't try to invalidate our cookie
    }

    public void testAutoLoginIfExpired() throws Exception {
        UserDetails user = new User("someone", "password", true, true, true,
                true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ABC")});

        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        services.setKey("key");
        services.setAuthenticationDao(new MockAuthenticationDao(user, false));
        services.afterPropertiesSet();

        Cookie cookie = new Cookie(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY,
                generateCorrectCookieContentForToken(System.currentTimeMillis()
                    - 1000000, "someone", "password", "key"));
        MockHttpServletRequest request = new MockHttpServletRequest(null, null,
                "null", new Cookie[] {cookie});
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);

        Cookie returnedCookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    public void testAutoLoginIfMissingThreeTokensInCookieValue()
        throws Exception {
        UserDetails user = new User("someone", "password", true, true, true,
                true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ABC")});

        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        services.setKey("key");
        services.setAuthenticationDao(new MockAuthenticationDao(user, false));
        services.afterPropertiesSet();

        Cookie cookie = new Cookie(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY,
                new String(Base64.encodeBase64("x".getBytes())));
        MockHttpServletRequest request = new MockHttpServletRequest(null, null,
                "null", new Cookie[] {cookie});
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);

        Cookie returnedCookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    public void testAutoLoginIfNotBase64Encoded() throws Exception {
        UserDetails user = new User("someone", "password", true, true, true,
                true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ABC")});

        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        services.setKey("key");
        services.setAuthenticationDao(new MockAuthenticationDao(user, false));
        services.afterPropertiesSet();

        Cookie cookie = new Cookie(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY,
                "NOT_BASE_64_ENCODED");
        MockHttpServletRequest request = new MockHttpServletRequest(null, null,
                "null", new Cookie[] {cookie});
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);

        Cookie returnedCookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    public void testAutoLoginIfSignatureBlocksDoesNotMatchExpectedValue()
        throws Exception {
        UserDetails user = new User("someone", "password", true, true, true,
                true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ABC")});

        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        services.setKey("key");
        services.setAuthenticationDao(new MockAuthenticationDao(user, false));
        services.afterPropertiesSet();

        Cookie cookie = new Cookie(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY,
                generateCorrectCookieContentForToken(System.currentTimeMillis()
                    + 1000000, "someone", "password", "WRONG_KEY"));
        MockHttpServletRequest request = new MockHttpServletRequest(null, null,
                "null", new Cookie[] {cookie});
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);

        Cookie returnedCookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    public void testAutoLoginIfTokenDoesNotContainANumberInCookieValue()
        throws Exception {
        UserDetails user = new User("someone", "password", true, true, true,
                true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ABC")});

        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        services.setKey("key");
        services.setAuthenticationDao(new MockAuthenticationDao(user, false));
        services.afterPropertiesSet();

        Cookie cookie = new Cookie(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY,
                new String(Base64.encodeBase64(
                        "username:NOT_A_NUMBER:signature".getBytes())));
        MockHttpServletRequest request = new MockHttpServletRequest(null, null,
                "null", new Cookie[] {cookie});
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);

        Cookie returnedCookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    public void testAutoLoginIfUserNotFound() throws Exception {
        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        services.setKey("key");
        services.setAuthenticationDao(new MockAuthenticationDao(null, true));
        services.afterPropertiesSet();

        Cookie cookie = new Cookie(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY,
                generateCorrectCookieContentForToken(System.currentTimeMillis()
                    + 1000000, "someone", "password", "key"));
        MockHttpServletRequest request = new MockHttpServletRequest(null, null,
                "null", new Cookie[] {cookie});
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNull(result);

        Cookie returnedCookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(returnedCookie);
        assertEquals(0, returnedCookie.getMaxAge());
    }

    public void testAutoLoginWithValidToken() throws Exception {
        UserDetails user = new User("someone", "password", true, true, true,
                true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ABC")});

        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        services.setKey("key");
        services.setAuthenticationDao(new MockAuthenticationDao(user, false));
        services.afterPropertiesSet();

        Cookie cookie = new Cookie(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY,
                generateCorrectCookieContentForToken(System.currentTimeMillis()
                    + 1000000, "someone", "password", "key"));
        MockHttpServletRequest request = new MockHttpServletRequest(null, null,
                "null", new Cookie[] {cookie});
        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication result = services.autoLogin(request, response);

        assertNotNull(result);

        UserDetails resultingUserDetails = (UserDetails) result.getPrincipal();

        assertEquals(user, resultingUserDetails);
    }

    public void testGettersSetters() {
        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        services.setAuthenticationDao(new MockAuthenticationDao(null, false));
        assertTrue(services.getAuthenticationDao() != null);

        services.setKey("d");
        assertEquals("d", services.getKey());

        assertEquals(TokenBasedRememberMeServices.DEFAULT_PARAMETER,
            services.getParameter());
        services.setParameter("some_param");
        assertEquals("some_param", services.getParameter());

        services.setTokenValiditySeconds(12);
        assertEquals(12, services.getTokenValiditySeconds());
    }

    public void testLoginFail() {
        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        MockHttpServletRequest request = new MockHttpServletRequest("fv");
        MockHttpServletResponse response = new MockHttpServletResponse();
        services.loginFail(request, response);

        Cookie cookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(cookie);
        assertEquals(0, cookie.getMaxAge());
    }

    public void testLoginSuccessIgnoredIfParameterNotSetOrFalse() {
        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        MockHttpServletRequest request = new MockHttpServletRequest("d");
        request.setParameter(TokenBasedRememberMeServices.DEFAULT_PARAMETER,
            "false");

        MockHttpServletResponse response = new MockHttpServletResponse();
        services.loginSuccess(request, response,
            new TestingAuthenticationToken("someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ABC")}));

        Cookie cookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNull(cookie);
    }

    public void testLoginSuccessNormalWithNonUserDetailsBasedPrincipal() {
        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        MockHttpServletRequest request = new MockHttpServletRequest("d");
        request.setParameter(TokenBasedRememberMeServices.DEFAULT_PARAMETER,
            "true");

        MockHttpServletResponse response = new MockHttpServletResponse();
        services.loginSuccess(request, response,
            new TestingAuthenticationToken("someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ABC")}));

        Cookie cookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(cookie);
        assertEquals(60 * 60 * 24 * 365 * 5, cookie.getMaxAge()); // 5 years
        assertTrue(Base64.isArrayByteBase64(cookie.getValue().getBytes()));
        assertTrue(new Date().before(
                new Date(determineExpiryTimeFromBased64EncodedToken(
                        cookie.getValue()))));
    }

    public void testLoginSuccessNormalWithUserDetailsBasedPrincipal() {
        TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
        MockHttpServletRequest request = new MockHttpServletRequest("d");
        request.setParameter(TokenBasedRememberMeServices.DEFAULT_PARAMETER,
            "true");

        MockHttpServletResponse response = new MockHttpServletResponse();
        UserDetails user = new User("someone", "password", true, true, true,
                true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ABC")});
        services.loginSuccess(request, response,
            new TestingAuthenticationToken(user, "ignored",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ABC")}));

        Cookie cookie = response.getCookieByName(TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY);
        assertNotNull(cookie);
        assertEquals(60 * 60 * 24 * 365 * 5, cookie.getMaxAge()); // 5 years
        assertTrue(Base64.isArrayByteBase64(cookie.getValue().getBytes()));
        assertTrue(new Date().before(
                new Date(determineExpiryTimeFromBased64EncodedToken(
                        cookie.getValue()))));
    }

    private long determineExpiryTimeFromBased64EncodedToken(String validToken) {
        String cookieAsPlainText = new String(Base64.decodeBase64(
                    validToken.getBytes()));
        String[] cookieTokens = StringUtils.delimitedListToStringArray(cookieAsPlainText,
                ":");

        if (cookieTokens.length == 3) {
            try {
                return new Long(cookieTokens[1]).longValue();
            } catch (NumberFormatException nfe) {}
        }

        return -1;
    }

    private String generateCorrectCookieContentForToken(long expiryTime,
        String username, String password, String key) {
        // format is:
        //     username + ":" + expiryTime + ":" + Md5Hex(username + ":" + expiryTime + ":" + password + ":" + key)
        String signatureValue = new String(DigestUtils.md5Hex(username + ":"
                    + expiryTime + ":" + password + ":" + key));
        String tokenValue = username + ":" + expiryTime + ":" + signatureValue;
        String tokenValueBase64 = new String(Base64.encodeBase64(
                    tokenValue.getBytes()));

        return tokenValueBase64;
    }

    //~ Inner Classes ==========================================================

    private class MockAuthenticationDao implements AuthenticationDao {
        private UserDetails toReturn;
        private boolean throwException;

        public MockAuthenticationDao(UserDetails toReturn,
            boolean throwException) {
            this.toReturn = toReturn;
            this.throwException = throwException;
        }

        public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
            if (throwException) {
                throw new UsernameNotFoundException("as requested by mock");
            }

            return toReturn;
        }
    }
}
