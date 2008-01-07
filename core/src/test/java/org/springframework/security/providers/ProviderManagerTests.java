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

package org.springframework.security.providers;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationServiceException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.MockApplicationEventPublisher;
import org.springframework.security.concurrent.ConcurrentSessionControllerImpl;
import org.springframework.security.concurrent.NullConcurrentSessionController;

import junit.framework.TestCase;

import java.util.Arrays;
import java.util.List;
import java.util.Vector;


/**
 * Tests {@link ProviderManager}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ProviderManagerTests extends TestCase {
    //~ Constructors ===================================================================================================

    public ProviderManagerTests() {
    }

    public ProviderManagerTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    private ProviderManager makeProviderManager() throws Exception {
        MockProvider provider1 = new MockProvider();
        List providers = new Vector();
        providers.add(provider1);

        ProviderManager mgr = new ProviderManager();
        mgr.setProviders(providers);

        mgr.afterPropertiesSet();

        return mgr;
    }

    private ProviderManager makeProviderManagerWithMockProviderWhichReturnsNullInList() {
        MockProviderWhichReturnsNull provider1 = new MockProviderWhichReturnsNull();
        MockProvider provider2 = new MockProvider();
        List providers = new Vector();
        providers.add(provider1);
        providers.add(provider2);

        ProviderManager mgr = new ProviderManager();
        mgr.setProviders(providers);

        return mgr;
    }

    public void testAuthenticationFails() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});

        ProviderManager mgr = makeProviderManager();
        mgr.setApplicationEventPublisher(new MockApplicationEventPublisher(true));

        try {
            mgr.authenticate(token);
            fail("Should have thrown ProviderNotFoundException");
        } catch (ProviderNotFoundException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticationSuccess() throws Exception {
        TestingAuthenticationToken token = new TestingAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});

        ProviderManager mgr = makeProviderManager();
        mgr.setApplicationEventPublisher(new MockApplicationEventPublisher(true));

        Authentication result = mgr.authenticate(token);

        if (!(result instanceof TestingAuthenticationToken)) {
            fail("Should have returned instance of TestingAuthenticationToken");
        }

        TestingAuthenticationToken castResult = (TestingAuthenticationToken) result;
        assertEquals("Test", castResult.getPrincipal());
        assertEquals("Password", castResult.getCredentials());
        assertEquals("ROLE_ONE", castResult.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", castResult.getAuthorities()[1].getAuthority());
    }

    public void testAuthenticationSuccessWhenFirstProviderReturnsNullButSecondAuthenticates() {
        TestingAuthenticationToken token = new TestingAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});

        ProviderManager mgr = makeProviderManagerWithMockProviderWhichReturnsNullInList();
        mgr.setApplicationEventPublisher(new MockApplicationEventPublisher(true));

        Authentication result = mgr.authenticate(token);

        if (!(result instanceof TestingAuthenticationToken)) {
            fail("Should have returned instance of TestingAuthenticationToken");
        }

        TestingAuthenticationToken castResult = (TestingAuthenticationToken) result;
        assertEquals("Test", castResult.getPrincipal());
        assertEquals("Password", castResult.getCredentials());
        assertEquals("ROLE_ONE", castResult.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", castResult.getAuthorities()[1].getAuthority());
    }

    public void testConcurrentSessionControllerConfiguration() throws Exception {
        ProviderManager target = new ProviderManager();

        //The NullConcurrentSessionController should be the default
        assertNotNull(target.getSessionController());
        assertTrue(target.getSessionController() instanceof NullConcurrentSessionController);

        ConcurrentSessionControllerImpl impl = new ConcurrentSessionControllerImpl();
        target.setSessionController(impl);
        assertEquals(impl, target.getSessionController());
    }

    public void testStartupFailsIfProviderListDoesNotContainingProviders() throws Exception {
        List providers = new Vector();
        providers.add("THIS_IS_NOT_A_PROVIDER");

        ProviderManager mgr = new ProviderManager();

        try {
            mgr.setProviders(providers);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfProviderListNotSet() throws Exception {
        ProviderManager mgr = new ProviderManager();

        try {
            mgr.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfProviderListNull() throws Exception {
        ProviderManager mgr = new ProviderManager();

        try {
            mgr.setProviders(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testSuccessfulStartup() throws Exception {
        ProviderManager mgr = makeProviderManager();
        mgr.afterPropertiesSet();
        assertTrue(true);
        assertEquals(1, mgr.getProviders().size());
    }

    public void testDetailsAreNotSetOnAuthenticationTokenIfAlreadySetByProvider() throws Exception {
        Object requestDetails = new String("(Request Details)");
        final Object resultDetails = new String("(Result Details)");
        ProviderManager authMgr = makeProviderManager();

        AuthenticationProvider provider = new AuthenticationProvider() {
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                ((TestingAuthenticationToken)authentication).setDetails(resultDetails);
                return authentication;
            }

            public boolean supports(Class authentication) {
                return true;
            }
        };

        authMgr.setProviders(Arrays.asList(new AuthenticationProvider[] {provider}));

        TestingAuthenticationToken request = createAuthenticationToken();
        request.setDetails(requestDetails);

        Authentication result = authMgr.authenticate(request);
        assertEquals(resultDetails, result.getDetails());
    }

    public void testDetailsAreSetOnAuthenticationTokenIfNotAlreadySetByProvider() throws Exception {
        Object details = new Object();
        ProviderManager authMgr = makeProviderManager();

        TestingAuthenticationToken request = createAuthenticationToken();
        request.setDetails(details);

        Authentication result = authMgr.authenticate(request);
        assertEquals(details, result.getDetails());
    }

    private TestingAuthenticationToken createAuthenticationToken() {
        return new TestingAuthenticationToken("name", "password", new GrantedAuthorityImpl[0]);
    }

    //~ Inner Classes ==================================================================================================

    private class MockProvider implements AuthenticationProvider {
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            if (supports(authentication.getClass())) {
                return authentication;
            } else {
                throw new AuthenticationServiceException("Don't support this class");
            }
        }

        public boolean supports(Class authentication) {
            if (TestingAuthenticationToken.class.isAssignableFrom(authentication)) {
                return true;
            } else {
                return false;
            }
        }
    }

    private class MockProviderWhichReturnsNull implements AuthenticationProvider {
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            if (supports(authentication.getClass())) {
                return null;
            } else {
                throw new AuthenticationServiceException("Don't support this class");
            }
        }

        public boolean supports(Class authentication) {
            if (TestingAuthenticationToken.class.isAssignableFrom(authentication)) {
                return true;
            } else {
                return false;
            }
        }
    }
}
