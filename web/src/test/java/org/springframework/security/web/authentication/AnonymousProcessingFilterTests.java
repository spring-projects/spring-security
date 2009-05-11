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

import static org.mockito.Mockito.mock;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.memory.UserAttribute;


/**
 * Tests {@link AnonymousProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AnonymousProcessingFilterTests extends TestCase {
    //~ Constructors ===================================================================================================

    public AnonymousProcessingFilterTests() {
        super();
    }

    public AnonymousProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    private void executeFilterInContainerSimulator(FilterConfig filterConfig, Filter filter, ServletRequest request,
        ServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        filter.init(filterConfig);
        filter.doFilter(request, response, filterChain);
        filter.destroy();
    }

    protected void setUp() throws Exception {
        super.setUp();
        SecurityContextHolder.clearContext();
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.clearContext();
    }

    public void testDetectsMissingKey() throws Exception {
        UserAttribute user = new UserAttribute();
        user.setPassword("anonymousUsername");
        user.addAuthority(new GrantedAuthorityImpl("ROLE_ANONYMOUS"));

        AnonymousProcessingFilter filter = new AnonymousProcessingFilter();
        filter.setUserAttribute(user);

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testDetectsUserAttribute() throws Exception {
        AnonymousProcessingFilter filter = new AnonymousProcessingFilter();
        filter.setKey("qwerty");

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGettersSetters() throws Exception {
        UserAttribute user = new UserAttribute();
        user.setPassword("anonymousUsername");
        user.addAuthority(new GrantedAuthorityImpl("ROLE_ANONYMOUS"));

        AnonymousProcessingFilter filter = new AnonymousProcessingFilter();
        filter.setKey("qwerty");
        filter.setUserAttribute(user);
        assertTrue(filter.isRemoveAfterRequest());
        filter.afterPropertiesSet();

        assertEquals("qwerty", filter.getKey());
        assertEquals(user, filter.getUserAttribute());
        filter.setRemoveAfterRequest(false);
        assertFalse(filter.isRemoveAfterRequest());
    }

    public void testOperationWhenAuthenticationExistsInContextHolder()
        throws Exception {
        // Put an Authentication object into the SecurityContextHolder
        Authentication originalAuth = new TestingAuthenticationToken("user", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A")});
        SecurityContextHolder.getContext().setAuthentication(originalAuth);

        // Setup our filter correctly
        UserAttribute user = new UserAttribute();
        user.setPassword("anonymousUsername");
        user.addAuthority(new GrantedAuthorityImpl("ROLE_ANONYMOUS"));

        AnonymousProcessingFilter filter = new AnonymousProcessingFilter();
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

    public void testOperationWhenNoAuthenticationInSecurityContextHolder() throws Exception {
        UserAttribute user = new UserAttribute();
        user.setPassword("anonymousUsername");
        user.addAuthority(new GrantedAuthorityImpl("ROLE_ANONYMOUS"));

        AnonymousProcessingFilter filter = new AnonymousProcessingFilter();
        filter.setKey("qwerty");
        filter.setUserAttribute(user);
        filter.setRemoveAfterRequest(false); // set to non-default value
        filter.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("x");
        executeFilterInContainerSimulator(mock(FilterConfig.class), filter, request, new MockHttpServletResponse(),
            new MockFilterChain(true));

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertEquals("anonymousUsername", auth.getPrincipal());
        assertEquals(new GrantedAuthorityImpl("ROLE_ANONYMOUS"), auth.getAuthorities().get(0));
        SecurityContextHolder.getContext().setAuthentication(null); // so anonymous fires again

        // Now test operation if we have removeAfterRequest = true
        filter.setRemoveAfterRequest(true); // set to default value
        executeFilterInContainerSimulator(mock(FilterConfig.class), filter, request, new MockHttpServletResponse(),
            new MockFilterChain(true));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    //~ Inner Classes ==================================================================================================

    private class MockFilterChain implements FilterChain {
        private boolean expectToProceed;

        public MockFilterChain(boolean expectToProceed) {
            this.expectToProceed = expectToProceed;
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
