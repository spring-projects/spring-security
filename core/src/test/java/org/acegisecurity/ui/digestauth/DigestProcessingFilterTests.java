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

package net.sf.acegisecurity.ui.digestauth;

import junit.framework.TestCase;

import net.sf.acegisecurity.DisabledException;
import net.sf.acegisecurity.MockFilterConfig;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.MockHttpSession;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.security.SecureContextImpl;
import net.sf.acegisecurity.context.security.SecureContextUtils;
import net.sf.acegisecurity.providers.dao.AuthenticationDao;
import net.sf.acegisecurity.providers.dao.UsernameNotFoundException;
import net.sf.acegisecurity.util.StringSplitUtils;

import org.apache.commons.codec.binary.Base64;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import org.springframework.dao.DataAccessException;

import org.springframework.util.StringUtils;

import java.io.IOException;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Tests {@link DigestProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DigestProcessingFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public DigestProcessingFilterTests() {
        super();
    }

    public DigestProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(DigestProcessingFilterTests.class);
    }

    public void testDoFilterWithNonHttpServletRequestDetected()
        throws Exception {
        DigestProcessingFilter filter = new DigestProcessingFilter();

        try {
            filter.doFilter(null, new MockHttpServletResponse(),
                new MockFilterChain());
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Can only process HttpServletRequest",
                expected.getMessage());
        }
    }

    public void testDoFilterWithNonHttpServletResponseDetected()
        throws Exception {
        DigestProcessingFilter filter = new DigestProcessingFilter();

        try {
            filter.doFilter(new MockHttpServletRequest(null, null), null,
                new MockFilterChain());
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Can only process HttpServletResponse",
                expected.getMessage());
        }
    }

    public void testExpiredNonceReturnsForbiddenWithStaleHeader()
        throws Exception {
        Map responseHeaderMap = generateValidHeaders(0);

        String username = "marissa";
        String realm = (String) responseHeaderMap.get("realm");
        String nonce = (String) responseHeaderMap.get("nonce");
        String uri = "/some_file.html";
        String qop = (String) responseHeaderMap.get("qop");
        String nc = "00000002";
        String cnonce = "c822c727a648aba7";
        String password = "koala";
        String responseDigest = DigestProcessingFilter.generateDigest(username,
                realm, password, "GET", uri, qop, nonce, nc, cnonce);

        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals(401, response.getError());

        String header = response.getHeader("WWW-Authenticate").substring(7);
        String[] headerEntries = StringUtils.commaDelimitedListToStringArray(header);
        Map headerMap = StringSplitUtils.splitEachArrayElementAndCreateMap(headerEntries,
                "=", "\"");
        assertEquals("true", headerMap.get("stale"));
    }

    public void testFilterIgnoresRequestsContainingNoAuthorizationHeader()
        throws Exception {
        // Setup our HTTP request
        Map headers = new HashMap();
        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
    }

    public void testGettersSetters() {
        DigestProcessingFilter filter = new DigestProcessingFilter();
        filter.setAuthenticationDao(new MockAuthenticationDao());
        assertTrue(filter.getAuthenticationDao() != null);

        filter.setAuthenticationEntryPoint(new DigestProcessingFilterEntryPoint());
        assertTrue(filter.getAuthenticationEntryPoint() != null);
    }

    public void testInvalidDigestAuthorizationTokenGeneratesError()
        throws Exception {
        // Setup our HTTP request
        Map headers = new HashMap();
        String token = "NOT_A_VALID_TOKEN_AS_MISSING_COLON";
        headers.put("Authorization",
            "Digest " + new String(Base64.encodeBase64(token.getBytes())));

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertEquals(401, response.getError());

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
    }

    public void testMalformedHeaderReturnsForbidden() throws Exception {
        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization", "Digest scsdcsdc");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals(401, response.getError());
    }

    public void testNonBase64EncodedNonceReturnsForbidden()
        throws Exception {
        Map responseHeaderMap = generateValidHeaders(60);

        String username = "marissa";
        String realm = (String) responseHeaderMap.get("realm");
        String nonce = "NOT_BASE_64_ENCODED";
        String uri = "/some_file.html";
        String qop = (String) responseHeaderMap.get("qop");
        String nc = "00000002";
        String cnonce = "c822c727a648aba7";
        String password = "koala";
        String responseDigest = DigestProcessingFilter.generateDigest(username,
                realm, password, "GET", uri, qop, nonce, nc, cnonce);

        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals(401, response.getError());
    }

    public void testNonceWithIncorrectSignatureForNumericFieldReturnsForbidden()
        throws Exception {
        Map responseHeaderMap = generateValidHeaders(60);

        String username = "marissa";
        String realm = (String) responseHeaderMap.get("realm");
        String nonce = new String(Base64.encodeBase64(
                    "123456:incorrectStringPassword".getBytes()));
        String uri = "/some_file.html";
        String qop = (String) responseHeaderMap.get("qop");
        String nc = "00000002";
        String cnonce = "c822c727a648aba7";
        String password = "koala";
        String responseDigest = DigestProcessingFilter.generateDigest(username,
                realm, password, "GET", uri, qop, nonce, nc, cnonce);

        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals(401, response.getError());
    }

    public void testNonceWithNonNumericFirstElementReturnsForbidden()
        throws Exception {
        Map responseHeaderMap = generateValidHeaders(60);

        String username = "marissa";
        String realm = (String) responseHeaderMap.get("realm");
        String nonce = new String(Base64.encodeBase64(
                    "hello:ignoredSecondElement".getBytes()));
        String uri = "/some_file.html";
        String qop = (String) responseHeaderMap.get("qop");
        String nc = "00000002";
        String cnonce = "c822c727a648aba7";
        String password = "koala";
        String responseDigest = DigestProcessingFilter.generateDigest(username,
                realm, password, "GET", uri, qop, nonce, nc, cnonce);

        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals(401, response.getError());
    }

    public void testNonceWithoutTwoColonSeparatedElementsReturnsForbidden()
        throws Exception {
        Map responseHeaderMap = generateValidHeaders(60);

        String username = "marissa";
        String realm = (String) responseHeaderMap.get("realm");
        String nonce = new String(Base64.encodeBase64(
                    "a base 64 string without a colon".getBytes()));
        String uri = "/some_file.html";
        String qop = (String) responseHeaderMap.get("qop");
        String nc = "00000002";
        String cnonce = "c822c727a648aba7";
        String password = "koala";
        String responseDigest = DigestProcessingFilter.generateDigest(username,
                realm, password, "GET", uri, qop, nonce, nc, cnonce);

        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals(401, response.getError());
    }

    public void testNormalOperation() throws Exception {
        Map responseHeaderMap = generateValidHeaders(60);

        String username = "marissa";
        String realm = (String) responseHeaderMap.get("realm");
        String nonce = (String) responseHeaderMap.get("nonce");
        String uri = "/some_file.html";
        String qop = (String) responseHeaderMap.get("qop");
        String nc = "00000002";
        String cnonce = "c822c727a648aba7";
        String password = "koala";
        String responseDigest = DigestProcessingFilter.generateDigest(username,
                realm, password, "GET", uri, qop, nonce, nc, cnonce);

        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNotNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals("marissa",
            ((UserDetails) SecureContextUtils.getSecureContext()
                                             .getAuthentication().getPrincipal())
            .getUsername());
    }

    public void testOtherAuthorizationSchemeIsIgnored()
        throws Exception {
        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization", "SOME_OTHER_AUTHENTICATION_SCHEME");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
    }

    public void testStartupDetectsMissingAuthenticationDao()
        throws Exception {
        try {
            DigestProcessingFilter filter = new DigestProcessingFilter();
            filter.setAuthenticationEntryPoint(new DigestProcessingFilterEntryPoint());
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An AuthenticationDao is required",
                expected.getMessage());
        }
    }

    public void testStartupDetectsMissingAuthenticationEntryPoint()
        throws Exception {
        try {
            DigestProcessingFilter filter = new DigestProcessingFilter();
            filter.setAuthenticationDao(new MockAuthenticationDao());
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A DigestProcessingFilterEntryPoint is required",
                expected.getMessage());
        }
    }

    public void testSuccessLoginThenFailureLoginResultsInSessionLoosingToken()
        throws Exception {
        Map responseHeaderMap = generateValidHeaders(60);

        String username = "marissa";
        String realm = (String) responseHeaderMap.get("realm");
        String nonce = (String) responseHeaderMap.get("nonce");
        String uri = "/some_file.html";
        String qop = (String) responseHeaderMap.get("qop");
        String nc = "00000002";
        String cnonce = "c822c727a648aba7";
        String password = "koala";
        String responseDigest = DigestProcessingFilter.generateDigest(username,
                realm, password, "GET", uri, qop, nonce, nc, cnonce);

        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNotNull(SecureContextUtils.getSecureContext().getAuthentication());

        // Now retry, giving an invalid nonce
        password = "WRONG_PASSWORD";
        responseDigest = DigestProcessingFilter.generateDigest(username, realm,
                password, "GET", uri, qop, nonce, nc, cnonce);

        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        request = new MockHttpServletRequest(headers, null,
                new MockHttpSession());
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        // Check we lost our previous authentication
        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals(401, response.getError());
    }

    public void testWrongCnonceBasedOnDigestReturnsForbidden()
        throws Exception {
        Map responseHeaderMap = generateValidHeaders(60);

        String username = "marissa";
        String realm = (String) responseHeaderMap.get("realm");
        String nonce = (String) responseHeaderMap.get("nonce");
        String uri = "/some_file.html";
        String qop = (String) responseHeaderMap.get("qop");
        String nc = "00000002";
        String cnonce = "NOT_SAME_AS_USED_FOR_DIGEST_COMPUTATION";
        String password = "koala";
        String responseDigest = DigestProcessingFilter.generateDigest(username,
                realm, password, "GET", uri, qop, nonce, nc, "DIFFERENT_CNONCE");

        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals(401, response.getError());
    }

    public void testWrongDigestReturnsForbidden() throws Exception {
        Map responseHeaderMap = generateValidHeaders(60);

        String username = "marissa";
        String realm = (String) responseHeaderMap.get("realm");
        String nonce = (String) responseHeaderMap.get("nonce");
        String uri = "/some_file.html";
        String qop = (String) responseHeaderMap.get("qop");
        String nc = "00000002";
        String cnonce = "c822c727a648aba7";
        String password = "WRONG_PASSWORD";
        String responseDigest = DigestProcessingFilter.generateDigest(username,
                realm, password, "GET", uri, qop, nonce, nc, cnonce);

        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals(401, response.getError());
    }

    public void testWrongRealmReturnsForbidden() throws Exception {
        Map responseHeaderMap = generateValidHeaders(60);

        String username = "marissa";
        String realm = "WRONG_REALM";
        String nonce = (String) responseHeaderMap.get("nonce");
        String uri = "/some_file.html";
        String qop = (String) responseHeaderMap.get("qop");
        String nc = "00000002";
        String cnonce = "c822c727a648aba7";
        String password = "koala";
        String responseDigest = DigestProcessingFilter.generateDigest(username,
                realm, password, "GET", uri, qop, nonce, nc, cnonce);

        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals(401, response.getError());
    }

    public void testWrongUsernameReturnsForbidden() throws Exception {
        Map responseHeaderMap = generateValidHeaders(60);

        String username = "NOT_A_KNOWN_USER";
        String realm = (String) responseHeaderMap.get("realm");
        String nonce = (String) responseHeaderMap.get("nonce");
        String uri = "/some_file.html";
        String qop = (String) responseHeaderMap.get("qop");
        String nc = "00000002";
        String cnonce = "c822c727a648aba7";
        String password = "koala";
        String responseDigest = DigestProcessingFilter.generateDigest(username,
                realm, password, "GET", uri, qop, nonce, nc, cnonce);

        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization",
            "Digest username=\"" + username + "\", realm=\"" + realm
            + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", response=\""
            + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\""
            + cnonce + "\"");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilter filter = (DigestProcessingFilter) ctx.getBean(
                "digestProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertNull(SecureContextUtils.getSecureContext().getAuthentication());
        assertEquals(401, response.getError());
    }

    protected void setUp() throws Exception {
        super.setUp();
        ContextHolder.setContext(new SecureContextImpl());
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        ContextHolder.setContext(null);
    }

    private void executeFilterInContainerSimulator(FilterConfig filterConfig,
        Filter filter, ServletRequest request, ServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
        filter.init(filterConfig);
        filter.doFilter(request, response, filterChain);
        filter.destroy();
    }

    private Map generateValidHeaders(int nonceValidityPeriod)
        throws Exception {
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/digestauth/filtertest-valid.xml");
        DigestProcessingFilterEntryPoint ep = (DigestProcessingFilterEntryPoint) ctx
            .getBean("digestProcessingFilterEntryPoint");
        ep.setNonceValiditySeconds(nonceValidityPeriod);

        MockHttpServletRequest request = new MockHttpServletRequest(
                "/some_path");
        MockHttpServletResponse response = new MockHttpServletResponse();

        ep.commence(request, response, new DisabledException("foobar"));

        // Break up response header
        String header = response.getHeader("WWW-Authenticate").substring(7);
        String[] headerEntries = StringUtils.commaDelimitedListToStringArray(header);
        Map headerMap = StringSplitUtils.splitEachArrayElementAndCreateMap(headerEntries,
                "=", "\"");

        return headerMap;
    }

    //~ Inner Classes ==========================================================

    private class MockAuthenticationDao implements AuthenticationDao {
        public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
            return null;
        }
    }

    private class MockFilterChain implements FilterChain {
        private boolean expectToProceed;

        public MockFilterChain(boolean expectToProceed) {
            this.expectToProceed = expectToProceed;
        }

        private MockFilterChain() {
            super();
        }

        public void doFilter(ServletRequest request, ServletResponse response)
            throws IOException, ServletException {
            if (expectToProceed) {
                assertTrue(true);
            } else {
                fail("Did not expect filter chain to proceed");
            }
        }
    }
}
