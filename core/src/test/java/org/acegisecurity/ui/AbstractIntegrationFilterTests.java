/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.ui;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.adapters.MockPrincipal;
import net.sf.acegisecurity.adapters.PrincipalAcegiUserToken;
import net.sf.acegisecurity.context.Context;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Tests {@link AbstractIntegrationFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AbstractIntegrationFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public AbstractIntegrationFilterTests() {
        super();
    }

    public AbstractIntegrationFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AbstractIntegrationFilterTests.class);
    }

    public void testContextHolderContentsPreserved() throws Exception {
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});
        MockAbstractIntegrationFilterImpl filter = new MockAbstractIntegrationFilterImpl(principal);
        MockFilterChain chain = new MockFilterChain(true, principal);

        MockSecureContextImpl secureContext = new MockSecureContextImpl(
                "FOO_BAR");
        ContextHolder.setContext(secureContext);
        assertEquals(secureContext, ContextHolder.getContext());

        executeFilterInContainerSimulator(filter, null, null, chain);

        MockSecureContextImpl after = (MockSecureContextImpl) ContextHolder
            .getContext();
        assertEquals(secureContext.getInfo(), after.getInfo());
        ContextHolder.setContext(null);
    }

    public void testContextHolderHasAuthenticationRemoved()
        throws Exception {
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});
        MockAbstractIntegrationFilterImpl filter = new MockAbstractIntegrationFilterImpl(principal);
        MockFilterChain chain = new MockFilterChain(true, principal);

        SecureContext secureContext = new SecureContextImpl();
        secureContext.setAuthentication(principal);
        ContextHolder.setContext(secureContext);
        assertEquals(secureContext, ContextHolder.getContext());

        executeFilterInContainerSimulator(filter, null, null, chain);

        SecureContext after = (SecureContext) ContextHolder.getContext();
        assertEquals(null, after.getAuthentication());
        ContextHolder.setContext(null);
    }

    public void testIgnoredWhenConcreteClassReturnsANonAuthenticationObject()
        throws Exception {
        MockPrincipal principal = new MockPrincipal();
        MockAbstractIntegrationFilterImpl filter = new MockAbstractIntegrationFilterImpl(principal);
        MockFilterChain chain = new MockFilterChain(false, null);

        Context before = ContextHolder.getContext();

        if (before != null) {
            if (before instanceof SecureContext) {
                assertEquals(null, ((SecureContext) before).getAuthentication());
            }
        }

        executeFilterInContainerSimulator(filter, null, null, chain);

        Context after = ContextHolder.getContext();

        if (after != null) {
            if (after instanceof SecureContext) {
                assertEquals(null, ((SecureContext) after).getAuthentication());
            }
        }
    }

    public void testIgnoredWhenConcreteClassReturnsNullAuthenticationObject()
        throws Exception {
        MockAbstractIntegrationFilterImpl filter = new MockAbstractIntegrationFilterImpl(null);
        MockFilterChain chain = new MockFilterChain(false, null);

        Context before = ContextHolder.getContext();

        if (before != null) {
            if (before instanceof SecureContext) {
                assertEquals(null, ((SecureContext) before).getAuthentication());
            }
        }

        executeFilterInContainerSimulator(filter, null, null, chain);

        Context after = ContextHolder.getContext();

        if (after != null) {
            if (after instanceof SecureContext) {
                assertEquals(null, ((SecureContext) after).getAuthentication());
            }
        }
    }

    public void testSuccessWhenConcreteClassReturnsValidAuthenticationObject()
        throws Exception {
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});
        MockAbstractIntegrationFilterImpl filter = new MockAbstractIntegrationFilterImpl(principal);
        MockFilterChain chain = new MockFilterChain(true, principal);

        Context before = ContextHolder.getContext();

        if (before != null) {
            if (before instanceof SecureContext) {
                assertEquals(null, ((SecureContext) before).getAuthentication());
            }
        }

        executeFilterInContainerSimulator(filter, null, null, chain);

        Context after = ContextHolder.getContext();

        if (after != null) {
            if (after instanceof SecureContext) {
                assertEquals(null, ((SecureContext) after).getAuthentication());
            }
        }
    }

    private void executeFilterInContainerSimulator(Filter filter,
        ServletRequest request, ServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
        filter.init(null);
        filter.doFilter(request, response, filterChain);
        filter.destroy();
    }

    //~ Inner Classes ==========================================================

    private class MockAbstractIntegrationFilterImpl
        extends AbstractIntegrationFilter {
        private Object extractFromContainerResult;

        public MockAbstractIntegrationFilterImpl(
            Object extractFromContainerResult) {
            this.extractFromContainerResult = extractFromContainerResult;
        }

        private MockAbstractIntegrationFilterImpl() {
            super();
        }

        public Object extractFromContainer(ServletRequest request) {
            return this.extractFromContainerResult;
        }
    }

    private class MockFilterChain implements FilterChain {
        private Authentication expectedAuthenticationObjectInContextHolder;
        private boolean expectContextHolderContainSecureContext = false;

        public MockFilterChain(
            boolean expectContextHolderContainSecureContext,
            Authentication expectedAuthenticationObjectInContextHolder) {
            if ((expectedAuthenticationObjectInContextHolder != null)
                && !expectContextHolderContainSecureContext) {
                throw new IllegalArgumentException(
                    "If an Authentication object is expected, the ContextHolder should contain a SecureContext");
            }

            this.expectContextHolderContainSecureContext = expectContextHolderContainSecureContext;
            this.expectedAuthenticationObjectInContextHolder = expectedAuthenticationObjectInContextHolder;
        }

        private MockFilterChain() {
            super();
        }

        public void doFilter(ServletRequest request, ServletResponse response)
            throws IOException, ServletException {
            if (expectContextHolderContainSecureContext) {
                Context context = ContextHolder.getContext();

                if (!(context instanceof SecureContext)) {
                    fail("ContextHolder should have contained SecureContext");
                }
            } else {
                if (ContextHolder.getContext() != null) {
                    fail("ContextHolder should have been null but wasn't");
                }
            }
        }
    }

    private class MockSecureContextImpl extends SecureContextImpl {
        private String info;

        public MockSecureContextImpl(String info) {
            this.info = info;
        }

        private MockSecureContextImpl() {
            super();
        }

        public String getInfo() {
            return this.info;
        }
    }
}
