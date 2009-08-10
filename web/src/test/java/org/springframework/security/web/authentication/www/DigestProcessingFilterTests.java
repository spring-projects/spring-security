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

package org.springframework.security.web.authentication.www;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.core.userdetails.memory.InMemoryDaoImpl;
import org.springframework.security.core.userdetails.memory.UserMap;
import org.springframework.security.core.userdetails.memory.UserMapEditor;
import org.springframework.util.StringUtils;


/**
 * Tests {@link DigestProcessingFilter}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public class DigestProcessingFilterTests {
    //~ Static fields/initializers =====================================================================================

    private static final String NC = "00000002";
    private static final String CNONCE = "c822c727a648aba7";
    private static final String REALM = "The Actual, Correct Realm Name";
    private static final String KEY = "springsecurity";
    private static final String QOP = "auth";
    private static final String USERNAME = "rod,ok";
    private static final String PASSWORD = "koala";
    private static final String REQUEST_URI = "/some_file.html";

    /**
     * A standard valid nonce with a validity period of 60 seconds
     */
    private static final String NONCE = generateNonce(60);

    //~ Instance fields ================================================================================================

    //    private ApplicationContext ctx;
    private DigestProcessingFilter filter;
    private MockHttpServletRequest request;


    //~ Methods ========================================================================================================

    private String createAuthorizationHeader(String username, String realm, String nonce, String uri,
                                             String responseDigest, String qop, String nc, String cnonce) {
        return "Digest username=\"" + username + "\", realm=\"" + realm + "\", nonce=\"" + nonce + "\", uri=\"" + uri
                + "\", response=\"" + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\"" + cnonce + "\"";
    }

    private MockHttpServletResponse executeFilterInContainerSimulator(Filter filter, final ServletRequest request,
                                                                      final boolean expectChainToProceed) throws ServletException, IOException {
        final MockHttpServletResponse response = new MockHttpServletResponse();

        Mockery jmockContext = new JUnit4Mockery();
        final FilterChain chain = jmockContext.mock(FilterChain.class);

        jmockContext.checking(new Expectations() {{
             exactly(expectChainToProceed ? 1 : 0).of(chain).doFilter(request, response);
        }});

        filter.doFilter(request, response, chain);

        jmockContext.assertIsSatisfied();
        return response;
    }

    private static String generateNonce(int validitySeconds) {
        long expiryTime = System.currentTimeMillis() + (validitySeconds * 1000);
        String signatureValue = new String(DigestUtils.md5Hex(expiryTime + ":" + KEY));
        String nonceValue = expiryTime + ":" + signatureValue;

        return new String(Base64.encodeBase64(nonceValue.getBytes()));
    }

    @After
    public void clearContext() throws Exception {
        SecurityContextHolder.clearContext();
    }

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();

        // Create User Details Service
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        UserMapEditor editor = new UserMapEditor();
        editor.setAsText("rod,ok=koala,ROLE_ONE,ROLE_TWO,enabled\r\n");
        dao.setUserMap((UserMap) editor.getValue());

        DigestProcessingFilterEntryPoint ep = new DigestProcessingFilterEntryPoint();
        ep.setRealmName(REALM);
        ep.setKey(KEY);

        filter = new DigestProcessingFilter();
        filter.setUserDetailsService(dao);
        filter.setAuthenticationEntryPoint(ep);

        request = new MockHttpServletRequest("GET", REQUEST_URI);
        request.setServletPath(REQUEST_URI);
    }

    @Test
    public void testExpiredNonceReturnsForbiddenWithStaleHeader()
            throws Exception {
        String nonce = generateNonce(0);
        String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET",
                REQUEST_URI, QOP, nonce, NC, CNONCE);

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        Thread.sleep(1000); // ensures token expired

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());

        String header = response.getHeader("WWW-Authenticate").toString().substring(7);
        String[] headerEntries = StringUtils.commaDelimitedListToStringArray(header);
        Map<String,String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");
        assertEquals("true", headerMap.get("stale"));
    }

    @Test
    public void testFilterIgnoresRequestsContainingNoAuthorizationHeader()
            throws Exception {
        executeFilterInContainerSimulator(filter, request, true);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testGettersSetters() {
        DigestProcessingFilter filter = new DigestProcessingFilter();
        filter.setUserDetailsService(new InMemoryDaoImpl());
        assertTrue(filter.getUserDetailsService() != null);

        filter.setAuthenticationEntryPoint(new DigestProcessingFilterEntryPoint());
        assertTrue(filter.getAuthenticationEntryPoint() != null);

        filter.setUserCache(null);
        assertNull(filter.getUserCache());
        filter.setUserCache(new NullUserCache());
        assertNotNull(filter.getUserCache());
    }

    @Test
    public void testInvalidDigestAuthorizationTokenGeneratesError()
            throws Exception {
        String token = "NOT_A_VALID_TOKEN_AS_MISSING_COLON";

        request.addHeader("Authorization", "Digest " + new String(Base64.encodeBase64(token.getBytes())));

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertEquals(401, response.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testMalformedHeaderReturnsForbidden() throws Exception {
        request.addHeader("Authorization", "Digest scsdcsdc");

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    @Test
    public void testNonBase64EncodedNonceReturnsForbidden() throws Exception {
        String nonce = "NOT_BASE_64_ENCODED";

        String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET",
                REQUEST_URI, QOP, nonce, NC, CNONCE);

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    @Test
    public void testNonceWithIncorrectSignatureForNumericFieldReturnsForbidden() throws Exception {
        String nonce = new String(Base64.encodeBase64("123456:incorrectStringPassword".getBytes()));
        String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET",
                REQUEST_URI, QOP, nonce, NC, CNONCE);

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    @Test
    public void testNonceWithNonNumericFirstElementReturnsForbidden() throws Exception {
        String nonce = new String(Base64.encodeBase64("hello:ignoredSecondElement".getBytes()));
        String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET",
                REQUEST_URI, QOP, nonce, NC, CNONCE);

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    @Test
    public void testNonceWithoutTwoColonSeparatedElementsReturnsForbidden() throws Exception {
        String nonce = new String(Base64.encodeBase64("a base 64 string without a colon".getBytes()));
        String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET",
                REQUEST_URI, QOP, nonce, NC, CNONCE);

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    @Test
    public void testNormalOperationWhenPasswordIsAlreadyEncoded() throws Exception {
        String encodedPassword = DigestAuthUtils.encodePasswordInA1Format(USERNAME, REALM, PASSWORD);
        String responseDigest = DigestAuthUtils.generateDigest(true, USERNAME, REALM, encodedPassword, "GET",
                REQUEST_URI, QOP, NONCE, NC, CNONCE);

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        executeFilterInContainerSimulator(filter, request, true);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(USERNAME,
                ((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername());
    }

    @Test
    public void testNormalOperationWhenPasswordNotAlreadyEncoded() throws Exception {
        String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET",
                REQUEST_URI, QOP, NONCE, NC, CNONCE);

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        executeFilterInContainerSimulator(filter, request, true);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(USERNAME,
                ((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername());
    }

    @Test
    public void otherAuthorizationSchemeIsIgnored()
            throws Exception {
        request.addHeader("Authorization", "SOME_OTHER_AUTHENTICATION_SCHEME");

        executeFilterInContainerSimulator(filter, request, true);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test(expected=IllegalArgumentException.class)
    public void startupDetectsMissingAuthenticationEntryPoint() throws Exception {
        DigestProcessingFilter filter = new DigestProcessingFilter();
        filter.setUserDetailsService(new InMemoryDaoImpl());
        filter.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void startupDetectsMissingUserDetailsService() throws Exception {
        DigestProcessingFilter filter = new DigestProcessingFilter();
        filter.setAuthenticationEntryPoint(new DigestProcessingFilterEntryPoint());
        filter.afterPropertiesSet();
    }

    @Test
    public void successfulLoginThenFailedLoginResultsInSessionLosingToken() throws Exception {
        String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET",
                REQUEST_URI, QOP, NONCE, NC, CNONCE);

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        executeFilterInContainerSimulator(filter, request, true);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());

        // Now retry, giving an invalid nonce
        responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, "WRONG_PASSWORD", "GET",
                REQUEST_URI, QOP, NONCE, NC, CNONCE);

        request = new MockHttpServletRequest();
        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        // Check we lost our previous authentication
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    @Test
    public void wrongCnonceBasedOnDigestReturnsForbidden() throws Exception {
        String cnonce = "NOT_SAME_AS_USED_FOR_DIGEST_COMPUTATION";

        String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET",
                REQUEST_URI, QOP, NONCE, NC, "DIFFERENT_CNONCE");

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, cnonce));

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    @Test
    public void wrongDigestReturnsForbidden() throws Exception {
        String password = "WRONG_PASSWORD";
        String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, password, "GET",
                REQUEST_URI, QOP, NONCE, NC, CNONCE);

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    @Test
    public void wrongRealmReturnsForbidden() throws Exception {
        String realm = "WRONG_REALM";
        String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, realm, PASSWORD, "GET",
                REQUEST_URI, QOP, NONCE, NC, CNONCE);

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, realm, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    @Test
    public void wrongUsernameReturnsForbidden() throws Exception {
        String responseDigest = DigestAuthUtils.generateDigest(false, "NOT_A_KNOWN_USER", REALM, PASSWORD,
                "GET", REQUEST_URI, QOP, NONCE, NC, CNONCE);

        request.addHeader("Authorization",
                createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }
}
