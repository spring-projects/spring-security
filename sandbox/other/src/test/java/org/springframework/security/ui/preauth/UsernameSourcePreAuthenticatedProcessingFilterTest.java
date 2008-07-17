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
package org.springframework.security.ui.preauth;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;

import junit.framework.TestCase;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.Authentication;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.ui.WebAuthenticationDetails;

/**
 * 
 * @author Valery Tydykov
 */
public class UsernameSourcePreAuthenticatedProcessingFilterTest extends TestCase {

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();
        // crear security context
        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public static final String PROJECT_ID_KEY = "projectIdKey";

    public static final String PROJECT_ID = "projectId";

    public static final String USERNAME_KEY = "usernameKey";

    public static final String USERNAME = "username";

    public void tearDown() throws Exception {
        // crear security context
        SecurityContextHolder.getContext().setAuthentication(null);
        super.tearDown();
    }

    public void testAttemptAuthenticationNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        // supply username in request header
        request.addHeader(USERNAME_KEY, USERNAME);

        UsernameSourcePreAuthenticatedProcessingFilter filter = new UsernameSourcePreAuthenticatedProcessingFilter();
        {
            MockAuthenticationManager authMgr = new MockAuthenticationManager(true);
            filter.setAuthenticationManager(authMgr);
        }
        {
            HeaderUsernameSource usernameSource = new HeaderUsernameSource();
            usernameSource.setUsernameKey(USERNAME_KEY);
            filter.setUsernameSource(usernameSource);
        }

        FilterChain filterChain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilterHttp(request, response, filterChain);

        Authentication result = SecurityContextHolder.getContext().getAuthentication();

        assertTrue(result != null);
        assertEquals(USERNAME, result.getPrincipal());
        assertEquals("127.0.0.1", ((WebAuthenticationDetails) result.getDetails())
            .getRemoteAddress());
    }

    public void testAttemptAuthenticationNoUsername() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        // no username in request

        UsernameSourcePreAuthenticatedProcessingFilter filter = new UsernameSourcePreAuthenticatedProcessingFilter();
        {
            HeaderUsernameSource usernameSource = new HeaderUsernameSource();
            usernameSource.setUsernameKey(USERNAME_KEY);
            filter.setUsernameSource(usernameSource);
        }

        FilterChain filterChain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilterHttp(request, response, filterChain);

        Authentication result = SecurityContextHolder.getContext().getAuthentication();
        assertTrue(result == null);
    }

    public void testAttemptAuthenticationContextPopulatingWebAuthenticationDetailsSourceFromHeader()
            throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();

        request.addHeader(USERNAME_KEY, USERNAME);
        request.addHeader(PROJECT_ID_KEY, PROJECT_ID);

        String key3 = "key3";
        String value3 = "value3";
        request.addHeader(key3, value3);

        UsernameSourcePreAuthenticatedProcessingFilter filter = new UsernameSourcePreAuthenticatedProcessingFilter();

        {
            MockAuthenticationManager authMgr = new MockAuthenticationManager(true);
            filter.setAuthenticationManager(authMgr);
        }
        {
            AttributesSourceWebAuthenticationDetailsSource authenticationDetailsSource = new AttributesSourceWebAuthenticationDetailsSource();
            authenticationDetailsSource.setClazz(AuthenticationDetailsImpl.class);
            {
                HeaderAttributesSource attributesSource = new HeaderAttributesSource();

                {
                    List keys = new ArrayList();
                    keys.add(PROJECT_ID_KEY);
                    keys.add(key3);
                    attributesSource.setKeys(keys);
                }

                authenticationDetailsSource.setAttributesSource(attributesSource);
            }

            filter.setAuthenticationDetailsSource(authenticationDetailsSource);
        }
        {
            HeaderUsernameSource usernameSource = new HeaderUsernameSource();
            usernameSource.setUsernameKey(USERNAME_KEY);
            filter.setUsernameSource(usernameSource);
        }

        FilterChain filterChain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilterHttp(request, response, filterChain);

        Authentication result = SecurityContextHolder.getContext().getAuthentication();

        assertTrue(result != null);
        assertEquals(USERNAME, result.getPrincipal());
        assertEquals("127.0.0.1", ((WebAuthenticationDetails) result.getDetails())
            .getRemoteAddress());
        assertEquals(PROJECT_ID, ((AuthenticationDetailsImpl) result.getDetails()).getAttributes()
            .get(PROJECT_ID_KEY));
        assertEquals(value3, ((AuthenticationDetailsImpl) result.getDetails()).getAttributes().get(
            key3));
    }

    public void testAttemptAuthenticationContextPopulatingWebAuthenticationDetailsSourceFromCookies()
            throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String usernameKey = "usernameKey1";
        String username = "username1";
        request.addHeader(usernameKey, username);

        String key2 = "key2";
        String value2 = "value2";
        String key3 = "key3";
        String value3 = "value3";

        {
            Cookie[] cookies = new Cookie[] { new Cookie(key2, value2), new Cookie(key3, value3) };
            request.setCookies(cookies);
        }

        UsernameSourcePreAuthenticatedProcessingFilter filter = new UsernameSourcePreAuthenticatedProcessingFilter();
        {
            MockAuthenticationManager authMgr = new MockAuthenticationManager(true);
            filter.setAuthenticationManager(authMgr);
        }
        {
            AttributesSourceWebAuthenticationDetailsSource authenticationDetailsSource = new AttributesSourceWebAuthenticationDetailsSource();
            authenticationDetailsSource.setClazz(AuthenticationDetailsImpl.class);

            {
                CookieAttributesSource attributesSource = new CookieAttributesSource();

                {
                    List keys = new ArrayList();
                    keys.add(key2);
                    keys.add(key3);
                    attributesSource.setKeys(keys);
                }

                authenticationDetailsSource.setAttributesSource(attributesSource);
            }

            filter.setAuthenticationDetailsSource(authenticationDetailsSource);
        }
        {
            HeaderUsernameSource usernameSource = new HeaderUsernameSource();
            usernameSource.setUsernameKey(usernameKey);
            filter.setUsernameSource(usernameSource);
        }

        FilterChain filterChain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilterHttp(request, response, filterChain);

        Authentication result = SecurityContextHolder.getContext().getAuthentication();

        assertTrue(result != null);
        assertEquals(username, result.getPrincipal());
        assertEquals("127.0.0.1", ((WebAuthenticationDetails) result.getDetails())
            .getRemoteAddress());
        assertEquals(value2, ((AuthenticationDetailsImpl) result.getDetails()).getAttributes().get(
            key2));
        assertEquals(value3, ((AuthenticationDetailsImpl) result.getDetails()).getAttributes().get(
            key3));

    }
}
