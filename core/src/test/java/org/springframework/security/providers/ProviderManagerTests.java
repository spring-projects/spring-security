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
import org.springframework.security.AccountStatusException;
import org.springframework.security.concurrent.ConcurrentSessionControllerImpl;
import org.springframework.security.concurrent.NullConcurrentSessionController;
import org.springframework.security.concurrent.ConcurrentLoginException;

import java.util.Arrays;
import java.util.List;
import java.util.Vector;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests {@link ProviderManager}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ProviderManagerTests {

    //~ Methods ========================================================================================================

    @Test(expected=ProviderNotFoundException.class)
    public void authenticationFailsWithUnsupportedToken() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});

        ProviderManager mgr = makeProviderManager();
        mgr.setApplicationEventPublisher(new MockApplicationEventPublisher(true));
        mgr.authenticate(token);
    }

    @Test
    public void authenticationSucceedsWithSupportedTokenAndReturnsExpectedObject() throws Exception {
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

    @Test
    public void authenticationSuccessWhenFirstProviderReturnsNullButSecondAuthenticates() {
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

    @Test
    public void concurrentSessionControllerConfiguration() throws Exception {
        ProviderManager target = new ProviderManager();

        //The NullConcurrentSessionController should be the default
        assertNotNull(target.getSessionController());
        assertTrue(target.getSessionController() instanceof NullConcurrentSessionController);

        ConcurrentSessionControllerImpl impl = new ConcurrentSessionControllerImpl();
        target.setSessionController(impl);
        assertEquals(impl, target.getSessionController());
    }

    @Test(expected=IllegalArgumentException.class)
    public void startupFailsIfProviderListDoesNotContainProviders() throws Exception {
        List providers = new Vector();
        providers.add("THIS_IS_NOT_A_PROVIDER");

        ProviderManager mgr = new ProviderManager();

        mgr.setProviders(providers);
    }

    @Test(expected=IllegalArgumentException.class)
    public void getProvidersFailsIfProviderListNotSet() throws Exception {
        ProviderManager mgr = new ProviderManager();

        mgr.afterPropertiesSet();
        mgr.getProviders();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testStartupFailsIfProviderListNull() throws Exception {
        ProviderManager mgr = new ProviderManager();

        mgr.setProviders(null);
    }

    @Test
    public void detailsAreNotSetOnAuthenticationTokenIfAlreadySetByProvider() throws Exception {
        Object requestDetails = "(Request Details)";
        final Object resultDetails = "(Result Details)";
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

        authMgr.setProviders(Arrays.asList(provider));

        TestingAuthenticationToken request = createAuthenticationToken();
        request.setDetails(requestDetails);

        Authentication result = authMgr.authenticate(request);
        assertEquals(resultDetails, result.getDetails());
    }

    @Test
    public void detailsAreSetOnAuthenticationTokenIfNotAlreadySetByProvider() throws Exception {
        Object details = new Object();
        ProviderManager authMgr = makeProviderManager();

        TestingAuthenticationToken request = createAuthenticationToken();
        request.setDetails(details);

        Authentication result = authMgr.authenticate(request);
        assertEquals(details, result.getDetails());
    }

    // SEC-546
    @Test(expected=AccountStatusException.class)
    public void accountStatusExceptionPreventsCallsToSubsequentProviders() throws Exception {
        ProviderManager authMgr = makeProviderManager();

        authMgr.setProviders(Arrays.asList(new MockProviderWhichThrowsAccountStatusException(),
                new MockProviderWhichThrowsConcurrentLoginException()) );

        authMgr.authenticate(createAuthenticationToken());
    }

    @Test(expected=ConcurrentLoginException.class)
    public void concurrentLoginExceptionPreventsCallsToSubsequentProviders() throws Exception {
        ProviderManager authMgr = makeProviderManager();

        authMgr.setProviders(Arrays.asList(new MockProviderWhichThrowsConcurrentLoginException(),
                new MockProviderWhichThrowsAccountStatusException()) );

        authMgr.authenticate(createAuthenticationToken());
    }

    private TestingAuthenticationToken createAuthenticationToken() {
        return new TestingAuthenticationToken("name", "password", new GrantedAuthorityImpl[0]);
    }

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

    private class MockProviderWhichThrowsAccountStatusException implements AuthenticationProvider {
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            throw new AccountStatusException("xxx") {};
        }

        public boolean supports(Class authentication) {
            return true;
        }
    }

    private class MockProviderWhichThrowsConcurrentLoginException implements AuthenticationProvider {
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            throw new ConcurrentLoginException("xxx") {};
        }

        public boolean supports(Class authentication) {
            return true;
        }
    }

}
