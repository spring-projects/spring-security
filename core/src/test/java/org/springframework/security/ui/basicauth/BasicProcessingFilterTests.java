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

package org.springframework.security.ui.basicauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.security.matcher.AuthenticationMatcher.anAuthenticationWithUsernameAndPassword;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.MockAuthenticationEntryPoint;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.MockFilterConfig;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.util.AuthorityUtils;


/**
 * Tests {@link BasicProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicProcessingFilterTests {
    //~ Instance fields ================================================================================================

    private BasicProcessingFilter filter;
    private Mockery jmock = new JUnit4Mockery();

    //~ Methods ========================================================================================================

    private MockHttpServletResponse executeFilterInContainerSimulator(Filter filter, final ServletRequest request,
                    final boolean expectChainToProceed) throws ServletException, IOException {
        filter.init(new MockFilterConfig());

        final MockHttpServletResponse response = new MockHttpServletResponse();
        Mockery jmockContext = new JUnit4Mockery();

        final FilterChain chain = jmockContext.mock(FilterChain.class);
        jmockContext.checking(new Expectations() {{
                exactly(expectChainToProceed ? 1 : 0).of(chain).doFilter(request, response);
            }});

        filter.doFilter(request, response, chain);
        filter.destroy();
        jmockContext.assertIsSatisfied();
        return response;
    }

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();

        final AuthenticationManager manager = jmock.mock(AuthenticationManager.class);
        final Authentication rod =
            new UsernamePasswordAuthenticationToken("rod", "koala", AuthorityUtils.createAuthorityList("ROLE_1"));
        jmock.checking(new Expectations() {{
            allowing(manager).authenticate(with(anAuthenticationWithUsernameAndPassword("rod", "koala")));
                will(returnValue(rod));
            allowing(manager).authenticate(with(any(Authentication.class)));
                will(throwException(new BadCredentialsException("")));
        }});

        filter = new BasicProcessingFilter();
        filter.setAuthenticationManager(manager);
        filter.setAuthenticationEntryPoint(new BasicProcessingFilterEntryPoint());
    }

    @After
    public void clearContext() throws Exception {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testFilterIgnoresRequestsContainingNoAuthorizationHeader() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/some_file.html");

        // Test
        executeFilterInContainerSimulator(filter, request, true);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testGettersSetters() {
        BasicProcessingFilter filter = new BasicProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager());
        assertTrue(filter.getAuthenticationManager() != null);

        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint("sx"));
        assertTrue(filter.getAuthenticationEntryPoint() != null);
    }

    @Test
    public void testInvalidBasicAuthorizationTokenIsIgnored() throws Exception {
        // Setup our HTTP request
        String token = "NOT_A_VALID_TOKEN_AS_MISSING_COLON";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request.setServletPath("/some_file.html");
        request.setSession(new MockHttpSession());

        // The filter chain shouldn't proceed
        executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testNormalOperation() throws Exception {
        // Setup our HTTP request
        String token = "rod:koala";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request.setServletPath("/some_file.html");
        request.setSession(new MockHttpSession());

        // Test
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        executeFilterInContainerSimulator(filter, request, true);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("rod", SecurityContextHolder.getContext().getAuthentication().getName());

    }

    @Test
    public void testOtherAuthorizationSchemeIsIgnored() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "SOME_OTHER_AUTHENTICATION_SCHEME");
        request.setServletPath("/some_file.html");

        // Test
        executeFilterInContainerSimulator(filter, request, true);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testStartupDetectsMissingAuthenticationEntryPoint() throws Exception {
        try {
            BasicProcessingFilter filter = new BasicProcessingFilter();
            filter.setAuthenticationManager(new MockAuthenticationManager());
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An AuthenticationEntryPoint is required", expected.getMessage());
        }
    }

    @Test(expected=IllegalArgumentException.class)
    public void testStartupDetectsMissingAuthenticationManager() throws Exception {
        BasicProcessingFilter filter = new BasicProcessingFilter();
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint("x"));
        filter.afterPropertiesSet();
    }

    @Test
    public void testSuccessLoginThenFailureLoginResultsInSessionLosingToken() throws Exception {
        // Setup our HTTP request
        String token = "rod:koala";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request.setServletPath("/some_file.html");
        request.setSession(new MockHttpSession());

        // Test
        executeFilterInContainerSimulator(filter, request, true);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("rod", SecurityContextHolder.getContext().getAuthentication().getName());

        // NOW PERFORM FAILED AUTHENTICATION
        // Setup our HTTP request
        token = "otherUser:WRONG_PASSWORD";
        request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request.setServletPath("/some_file.html");
        request.setSession(new MockHttpSession());

        // Test - the filter chain will not be invoked, as we get a 403 forbidden response
        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    @Test
    public void testWrongPasswordContinuesFilterChainIfIgnoreFailureIsTrue() throws Exception {
        // Setup our HTTP request
        String token = "rod:WRONG_PASSWORD";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request.setServletPath("/some_file.html");
        request.setSession(new MockHttpSession());

        filter.setIgnoreFailure(true);
        assertTrue(filter.isIgnoreFailure());

        // Test - the filter chain will be invoked, as we've set ignoreFailure = true
        executeFilterInContainerSimulator(filter, request, true);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testWrongPasswordReturnsForbiddenIfIgnoreFailureIsFalse() throws Exception {
        // Setup our HTTP request
        String token = "rod:WRONG_PASSWORD";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request.setServletPath("/some_file.html");
        request.setSession(new MockHttpSession());
        assertFalse(filter.isIgnoreFailure());

        // Test - the filter chain will not be invoked, as we get a 403 forbidden response
        MockHttpServletResponse response = executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }
}
