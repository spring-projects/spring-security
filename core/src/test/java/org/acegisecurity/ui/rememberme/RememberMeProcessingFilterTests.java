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

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;


/**
 * Tests {@link RememberMeProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RememberMeProcessingFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public RememberMeProcessingFilterTests() {
        super();
    }

    public RememberMeProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(RememberMeProcessingFilterTests.class);
    }
    
    public void testDoFilterWithNonHttpServletRequestDetected()
    throws Exception {
        RememberMeProcessingFilter filter = new RememberMeProcessingFilter();

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
        RememberMeProcessingFilter filter = new RememberMeProcessingFilter();

    try {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("dc");
        filter.doFilter(request, null,
            new MockFilterChain());
        fail("Should have thrown ServletException");
    } catch (ServletException expected) {
        assertEquals("Can only process HttpServletResponse",
            expected.getMessage());
    }
}

    public void testDetectsRememberMeServicesProperty() throws Exception {
        RememberMeProcessingFilter filter = new RememberMeProcessingFilter();
        // check default is NullRememberMeServices
        assertEquals(NullRememberMeServices.class, filter.getRememberMeServices().getClass());
        
        // check getter/setter
        filter.setRememberMeServices(new TokenBasedRememberMeServices());
        assertEquals(TokenBasedRememberMeServices.class, filter.getRememberMeServices().getClass());

        // check detects if made null
        filter.setRememberMeServices(null);
        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
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
    	Authentication remembered = new TestingAuthenticationToken("remembered",
                "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_REMEMBERED")});
        RememberMeProcessingFilter filter = new RememberMeProcessingFilter();
        filter.setRememberMeServices(new MockRememberMeServices(remembered));
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
    	Authentication remembered = new TestingAuthenticationToken("remembered",
                "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_REMEMBERED")});
        RememberMeProcessingFilter filter = new RememberMeProcessingFilter();
        filter.setRememberMeServices(new MockRememberMeServices(remembered));
        filter.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("x");
        executeFilterInContainerSimulator(new MockFilterConfig(), filter,
                request, new MockHttpServletResponse(),
            new MockFilterChain(true));

        Authentication auth = SecureContextUtils.getSecureContext()
                                                .getAuthentication();
        
        // Ensure filter setup with our remembered authentication object
        assertEquals(remembered,
                SecureContextUtils.getSecureContext().getAuthentication());
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
    
    private class MockRememberMeServices implements RememberMeServices
	{
    	private Authentication authToReturn;
    	
    	public MockRememberMeServices(Authentication authToReturn) {
    		this.authToReturn = authToReturn;
    	}
    	
		public Authentication autoLogin(HttpServletRequest request,
				HttpServletResponse response) {
			return authToReturn;
		}
		public void loginFail(HttpServletRequest request,
				HttpServletResponse response) {
		}
		public void loginSuccess(HttpServletRequest request,
				HttpServletResponse response,
				Authentication successfulAuthentication) {
		}
}
}
