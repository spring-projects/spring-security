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

package org.springframework.security.web.authentication;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.*;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.memory.UserAttribute;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;


/**
 * Tests {@link AnonymousAuthenticationFilter}.
 *
 * @author Ben Alex
 */
public class AnonymousAuthenticationFilterTests {

    //~ Methods ========================================================================================================

    private void executeFilterInContainerSimulator(FilterConfig filterConfig, Filter filter, ServletRequest request,
        ServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        filter.doFilter(request, response, filterChain);
    }

    @Before
    @After
    public void clearContext() throws Exception {
        SecurityContextHolder.clearContext();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDetectsMissingKey() throws Exception {
        UserAttribute user = new UserAttribute();
        user.setPassword("anonymousUsername");
        user.addAuthority(new SimpleGrantedAuthority("ROLE_ANONYMOUS"));

        AnonymousAuthenticationFilter filter = new AnonymousAuthenticationFilter();
        filter.setUserAttribute(user);
        filter.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testDetectsUserAttribute() throws Exception {
        AnonymousAuthenticationFilter filter = new AnonymousAuthenticationFilter();
        filter.setKey("qwerty");
        filter.afterPropertiesSet();
    }

    @Test
    public void testGettersSetters() throws Exception {
        UserAttribute user = new UserAttribute();
        user.setPassword("anonymousUsername");
        user.addAuthority(new SimpleGrantedAuthority("ROLE_ANONYMOUS"));

        AnonymousAuthenticationFilter filter = new AnonymousAuthenticationFilter();
        filter.setKey("qwerty");
        filter.setUserAttribute(user);
        filter.afterPropertiesSet();

        assertEquals("qwerty", filter.getKey());
        assertEquals(user, filter.getUserAttribute());
    }

    @Test
    public void testOperationWhenAuthenticationExistsInContextHolder()
        throws Exception {
        // Put an Authentication object into the SecurityContextHolder
        Authentication originalAuth = new TestingAuthenticationToken("user", "password", "ROLE_A");
        SecurityContextHolder.getContext().setAuthentication(originalAuth);

        // Setup our filter correctly
        UserAttribute user = new UserAttribute();
        user.setPassword("anonymousUsername");
        user.addAuthority(new SimpleGrantedAuthority("ROLE_ANONYMOUS"));

        AnonymousAuthenticationFilter filter = new AnonymousAuthenticationFilter();
        filter.setKey("qwerty");
        filter.setUserAttribute(user);
        filter.afterPropertiesSet();

        // Test
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("x");
        executeFilterInContainerSimulator(mock(FilterConfig.class), filter, request, new MockHttpServletResponse(),
            new MockFilterChain(true));

        // Ensure filter didn't change our original object
        assertEquals(originalAuth, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testOperationWhenNoAuthenticationInSecurityContextHolder() throws Exception {
        UserAttribute user = new UserAttribute();
        user.setPassword("anonymousUsername");
        user.addAuthority(new SimpleGrantedAuthority("ROLE_ANONYMOUS"));

        AnonymousAuthenticationFilter filter = new AnonymousAuthenticationFilter();
        filter.setKey("qwerty");
        filter.setUserAttribute(user);
        filter.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("x");
        executeFilterInContainerSimulator(mock(FilterConfig.class), filter, request, new MockHttpServletResponse(),
            new MockFilterChain(true));

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertEquals("anonymousUsername", auth.getPrincipal());
        assertTrue(AuthorityUtils.authorityListToSet(auth.getAuthorities()).contains("ROLE_ANONYMOUS"));
        SecurityContextHolder.getContext().setAuthentication(null); // so anonymous fires again
    }

    //~ Inner Classes ==================================================================================================

    private class MockFilterChain implements FilterChain {
        private boolean expectToProceed;

        public MockFilterChain(boolean expectToProceed) {
            this.expectToProceed = expectToProceed;
        }

        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            if (!expectToProceed) {
                fail("Did not expect filter chain to proceed");
            }
        }
    }
}
