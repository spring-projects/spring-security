/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;
import org.springframework.context.MessageSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;

/**
 * Tests {@link ProviderManager}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("unchecked")
public class ProviderManagerTests {

    @Test(expected=ProviderNotFoundException.class)
    public void authenticationFailsWithUnsupportedToken() throws Exception {
        Authentication token = new AbstractAuthenticationToken (null) {
            public Object getCredentials() {
                return "";
            }

            public Object getPrincipal() {
                return "";
            }
        };
        ProviderManager mgr = makeProviderManager();
        mgr.setMessageSource(mock(MessageSource.class));
        mgr.authenticate(token);
    }

    @Test
    public void credentialsAreClearedByDefault() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password");
        ProviderManager mgr = makeProviderManager();
        Authentication result = mgr.authenticate(token);
        assertNull(result.getCredentials());

        mgr.setEraseCredentialsAfterAuthentication(false);
        token = new UsernamePasswordAuthenticationToken("Test", "Password");
        result = mgr.authenticate(token);
        assertNotNull(result.getCredentials());
    }

    @Test
    public void authenticationSucceedsWithSupportedTokenAndReturnsExpectedObject() throws Exception {
        final Authentication a = mock(Authentication.class);
        ProviderManager mgr = new ProviderManager();
        AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
        mgr.setAuthenticationEventPublisher(publisher);
        mgr.setProviders(Arrays.asList(createProviderWhichReturns(a)));

        Authentication result = mgr.authenticate(a);
        assertEquals(a, result);
        verify(publisher).publishAuthenticationSuccess(result);
    }

    @Test
    public void authenticationSucceedsWhenFirstProviderReturnsNullButSecondAuthenticates() {
        final Authentication a = mock(Authentication.class);
        ProviderManager mgr = new ProviderManager();
        AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
        mgr.setAuthenticationEventPublisher(publisher);
        mgr.setProviders(Arrays.asList(createProviderWhichReturns(null), createProviderWhichReturns(a)));

        Authentication result = mgr.authenticate(a);
        assertSame(a, result);
        verify(publisher).publishAuthenticationSuccess(result);
    }

    @Test(expected=IllegalArgumentException.class)
    public void startupFailsIfProviderListDoesNotContainProviders() throws Exception {
        List<Object> providers = new ArrayList<Object>();
        providers.add("THIS_IS_NOT_A_PROVIDER");

        ProviderManager mgr = new ProviderManager();

        mgr.setProviders(providers);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testStartupFailsIfProvidersNotSet() throws Exception {
        ProviderManager mgr = new ProviderManager();
        mgr.afterPropertiesSet();
    }

    @Test
    public void detailsAreNotSetOnAuthenticationTokenIfAlreadySetByProvider() throws Exception {
        Object requestDetails = "(Request Details)";
        final Object resultDetails = "(Result Details)";
        ProviderManager authMgr = makeProviderManager();

        // A provider which sets the details object
        AuthenticationProvider provider = new AuthenticationProvider() {
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                ((TestingAuthenticationToken)authentication).setDetails(resultDetails);
                return authentication;
            }

            public boolean supports(Class<?> authentication) {
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
        assertNotNull(result.getCredentials());
        assertSame(details, result.getDetails());
    }

    @Test
    public void authenticationExceptionIsIgnoredIfLaterProviderAuthenticates() throws Exception {
        ProviderManager mgr = new ProviderManager();
        final Authentication authReq = mock(Authentication.class);
        mgr.setProviders(Arrays.asList(createProviderWhichThrows(new BadCredentialsException("", new Throwable())),
                createProviderWhichReturns(authReq)));
        assertSame(authReq, mgr.authenticate(mock(Authentication.class)));
    }

    @Test
    public void authenticationExceptionIsRethrownIfNoLaterProviderAuthenticates() throws Exception {
        ProviderManager mgr = new ProviderManager();

        mgr.setProviders(Arrays.asList(createProviderWhichThrows(new BadCredentialsException("", "extra")),
                createProviderWhichReturns(null)));
        try {
            mgr.authenticate(mock(Authentication.class));
            fail("Expected BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertEquals("extra", expected.getExtraInformation());
        }
    }

    // SEC-546
    @Test
    public void accountStatusExceptionPreventsCallsToSubsequentProviders() throws Exception {
        ProviderManager authMgr = makeProviderManager();
        AuthenticationProvider iThrowAccountStatusException = createProviderWhichThrows(new AccountStatusException(""){});
        AuthenticationProvider otherProvider = mock(AuthenticationProvider.class);

        authMgr.setProviders(Arrays.asList(iThrowAccountStatusException, otherProvider));

        try {
            authMgr.authenticate(mock(Authentication.class));
            fail("Expected AccountStatusException");
        } catch (AccountStatusException expected) {
        }
        verifyZeroInteractions(otherProvider);
    }

    @Test
    public void extraInformationIsClearedIfFlagIsSet() throws Exception {
        ProviderManager authMgr = makeProviderManager();
        AuthenticationProvider iThrowAccountStatusException = createProviderWhichThrows(new AccountStatusException("", "extra"){});

        authMgr.setProviders(Arrays.asList(iThrowAccountStatusException));
        authMgr.setClearExtraInformation(true);

        try {
            authMgr.authenticate(mock(Authentication.class));
            fail("Expected AccountStatusException");
        } catch (AccountStatusException expected) {
            assertNull(expected.getExtraInformation());
        }
    }

    @Test
    public void parentAuthenticationIsUsedIfProvidersDontAuthenticate() throws Exception {
        AuthenticationManager parent = mock(AuthenticationManager.class);
        Authentication authReq = mock(Authentication.class);
        when(parent.authenticate(authReq)).thenReturn(authReq);
        ProviderManager mgr = new ProviderManager(Arrays.asList(mock(AuthenticationProvider.class)), parent);
        assertSame(authReq, mgr.authenticate(authReq));
    }

    @Test
    public void parentIsNotCalledIfAccountStatusExceptionIsThrown() throws Exception {
        AuthenticationProvider iThrowAccountStatusException =
                createProviderWhichThrows(new AccountStatusException("", new Throwable()){});
        AuthenticationManager parent = mock(AuthenticationManager.class);
        ProviderManager mgr = new ProviderManager(Arrays.asList(iThrowAccountStatusException), parent);
        try {
            mgr.authenticate(mock(Authentication.class));
            fail("Expected exception");
        } catch (AccountStatusException expected) {
        }
        verifyZeroInteractions(parent);
    }

    @Test
    public void providerNotFoundFromParentIsIgnored() throws Exception {
        ProviderManager mgr = new ProviderManager();
        final Authentication authReq = mock(Authentication.class);
        AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
        mgr.setAuthenticationEventPublisher(publisher);
        // Set a provider that throws an exception - this is the exception we expect to be propagated
        mgr.setProviders(Arrays.asList(createProviderWhichThrows(new BadCredentialsException(""))));
        AuthenticationManager parent = mock(AuthenticationManager.class);
        when(parent.authenticate(authReq)).thenThrow(new ProviderNotFoundException(""));
        mgr.setParent(parent);
        try {
            mgr.authenticate(authReq);
            fail("Expected exception");
        } catch (BadCredentialsException expected) {
            verify(publisher).publishAuthenticationFailure(expected, authReq);
        }
    }

    @Test
    public void authenticationExceptionFromParentOverridesPreviousOnes() throws Exception {
        AuthenticationManager parent = mock(AuthenticationManager.class);
        ProviderManager mgr = new ProviderManager(
                Arrays.asList(createProviderWhichThrows(new BadCredentialsException(""))), parent);
        final Authentication authReq = mock(Authentication.class);
        AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
        mgr.setAuthenticationEventPublisher(publisher);
        // Set a provider that throws an exception - this is the exception we expect to be propagated
        final BadCredentialsException expected = new BadCredentialsException("I'm the one from the parent");
        when(parent.authenticate(authReq)).thenThrow(expected);
        try {
            mgr.authenticate(authReq);
            fail("Expected exception");
        } catch (BadCredentialsException e) {
            assertSame(expected, e);
            assertSame(authReq, e.getAuthentication());
        }
        verify(publisher).publishAuthenticationFailure(expected, authReq);
    }

    @Test
    @SuppressWarnings("deprecation")
    public void statusExceptionIsPublished() throws Exception {
        AuthenticationManager parent = mock(AuthenticationManager.class);
        final LockedException expected = new LockedException("");
        ProviderManager mgr = new ProviderManager(
                Arrays.asList(createProviderWhichThrows(expected)), parent);
        final Authentication authReq = mock(Authentication.class);
        AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
        mgr.setAuthenticationEventPublisher(publisher);
        try {
            mgr.authenticate(authReq);
            fail("Expected exception");
        } catch (LockedException e) {
            assertSame(expected, e);
            assertSame(authReq, e.getAuthentication());
        }
        verify(publisher).publishAuthenticationFailure(expected, authReq);
    }

    // SEC-2367
    @Test
    public void providerThrowsInternalAuthenticationServiceException() {
        InternalAuthenticationServiceException expected = new InternalAuthenticationServiceException("Expected");
        ProviderManager mgr = new ProviderManager(
                Arrays.asList(createProviderWhichThrows(expected), createProviderWhichThrows(new BadCredentialsException("Oops"))), null);
        final Authentication authReq = mock(Authentication.class);

        try {
            mgr.authenticate(authReq);
            fail("Expected Exception");
        } catch(InternalAuthenticationServiceException success) {}
    }

    private AuthenticationProvider createProviderWhichThrows(final AuthenticationException e) {
        AuthenticationProvider provider = mock(AuthenticationProvider.class);
        when(provider.supports(any(Class.class))).thenReturn(true);
        when(provider.authenticate(any(Authentication.class))).thenThrow(e);

        return provider;
    }

    private AuthenticationProvider createProviderWhichReturns(final Authentication a) {
        AuthenticationProvider provider = mock(AuthenticationProvider.class);
        when(provider.supports(any(Class.class))).thenReturn(true);
        when(provider.authenticate(any(Authentication.class))).thenReturn(a);

        return provider;
    }

    private TestingAuthenticationToken createAuthenticationToken() {
        return new TestingAuthenticationToken("name", "password", new ArrayList<GrantedAuthority>(0));
    }

    private ProviderManager makeProviderManager() throws Exception {
        MockProvider provider1 = new MockProvider();
        List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>();
        providers.add(provider1);

        return new ProviderManager(providers);
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

        public boolean supports(Class<?> authentication) {
            return TestingAuthenticationToken.class.isAssignableFrom(authentication) ||
                    UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        }
    }
}
