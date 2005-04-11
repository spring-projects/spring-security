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

package net.sf.acegisecurity.providers.anonymous;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.MockFilterConfig;



import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.security.SecureContext;
import net.sf.acegisecurity.context.security.SecureContextImpl;
import net.sf.acegisecurity.context.security.SecureContextUtils;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;
import net.sf.acegisecurity.providers.dao.memory.UserAttribute;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;


/**
 * Tests {@link AnonymousProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AnonymousProcessingFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public AnonymousProcessingFilterTests() {
        super();
    }

    public AnonymousProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AnonymousProcessingFilterTests.class);
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
        filter.afterPropertiesSet();

        assertEquals("qwerty", filter.getKey());
        assertEquals(user, filter.getUserAttribute());
    }

    public void testOperationWhenAuthenticationExistsInContextHolder()
        throws Exception {
        // Put an Authentication object into the ContextHolder
        SecureContext sc = SecureContextUtils.getSecureContext();
        Authentication originalAuth = new TestingAuthenticationToken("user",
                "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A")});
        sc.setAuthentication(originalAuth);
        ContextHolder.setContext(sc);

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
        executeFilterInContainerSimulator(new MockFilterConfig(), filter,
                request, new MockHttpServletResponse(),
            new MockFilterChain(true));

        // Ensure filter didn't change our original object
        assertEquals(originalAuth,
            SecureContextUtils.getSecureContext().getAuthentication());
    }

    public void testOperationWhenNoAuthenticationInContextHolder()
        throws Exception {
        UserAttribute user = new UserAttribute();
        user.setPassword("anonymousUsername");
        user.addAuthority(new GrantedAuthorityImpl("ROLE_ANONYMOUS"));

        AnonymousProcessingFilter filter = new AnonymousProcessingFilter();
        filter.setKey("qwerty");
        filter.setUserAttribute(user);
        filter.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("x");
        executeFilterInContainerSimulator(new MockFilterConfig(), filter,
                request, new MockHttpServletResponse(),
            new MockFilterChain(true));

        Authentication auth = SecureContextUtils.getSecureContext()
                                                .getAuthentication();
        assertEquals("anonymousUsername", auth.getPrincipal());
        assertEquals(new GrantedAuthorityImpl("ROLE_ANONYMOUS"),
            auth.getAuthorities()[0]);
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

    //~ Inner Classes ==========================================================

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
