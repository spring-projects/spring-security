/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication;

import org.junit.Test;
import org.springframework.context.MessageSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.*;

/**
 * Tests {@link ProviderManager}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("unchecked")
public class ProviderManagerTests {

	@Test(expected = ProviderNotFoundException.class)
	public void authenticationFailsWithUnsupportedToken() throws Exception {
		Authentication token = new AbstractAuthenticationToken(null) {
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
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				"Test", "Password");
		ProviderManager mgr = makeProviderManager();
		Authentication result = mgr.authenticate(token);
		assertThat(result.getCredentials()).isNull();

		mgr.setEraseCredentialsAfterAuthentication(false);
		token = new UsernamePasswordAuthenticationToken("Test", "Password");
		result = mgr.authenticate(token);
		assertThat(result.getCredentials()).isNotNull();
	}

	@Test
	public void authenticationSucceedsWithSupportedTokenAndReturnsExpectedObject()
			throws Exception {
		final Authentication a = mock(Authentication.class);
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(createProviderWhichReturns(a)));
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		mgr.setAuthenticationEventPublisher(publisher);

		Authentication result = mgr.authenticate(a);
		assertThat(result).isEqualTo(a);
		verify(publisher).publishAuthenticationSuccess(result);
	}

	@Test
	public void authenticationSucceedsWhenFirstProviderReturnsNullButSecondAuthenticates() {
		final Authentication a = mock(Authentication.class);
		ProviderManager mgr = new ProviderManager(Arrays.asList(
				createProviderWhichReturns(null), createProviderWhichReturns(a)));
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		mgr.setAuthenticationEventPublisher(publisher);

		Authentication result = mgr.authenticate(a);
		assertThat(result).isSameAs(a);
		verify(publisher).publishAuthenticationSuccess(result);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testStartupFailsIfProvidersNotSet() throws Exception {
		new ProviderManager(null);
	}

	@Test
	public void detailsAreNotSetOnAuthenticationTokenIfAlreadySetByProvider()
			throws Exception {
		Object requestDetails = "(Request Details)";
		final Object resultDetails = "(Result Details)";

		// A provider which sets the details object
		AuthenticationProvider provider = new AuthenticationProvider() {
			public Authentication authenticate(Authentication authentication)
					throws AuthenticationException {
				((TestingAuthenticationToken) authentication).setDetails(resultDetails);
				return authentication;
			}

			public boolean supports(Class<?> authentication) {
				return true;
			}
		};

		ProviderManager authMgr = new ProviderManager(Arrays.asList(provider));

		TestingAuthenticationToken request = createAuthenticationToken();
		request.setDetails(requestDetails);

		Authentication result = authMgr.authenticate(request);
		assertThat(result.getDetails()).isEqualTo(resultDetails);
	}

	@Test
	public void detailsAreSetOnAuthenticationTokenIfNotAlreadySetByProvider()
			throws Exception {
		Object details = new Object();
		ProviderManager authMgr = makeProviderManager();

		TestingAuthenticationToken request = createAuthenticationToken();
		request.setDetails(details);

		Authentication result = authMgr.authenticate(request);
		assertThat(result.getCredentials()).isNotNull();
		assertThat(result.getDetails()).isSameAs(details);
	}

	@Test
	public void authenticationExceptionIsIgnoredIfLaterProviderAuthenticates()
			throws Exception {
		final Authentication authReq = mock(Authentication.class);
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(createProviderWhichThrows(new BadCredentialsException("",
						new Throwable())), createProviderWhichReturns(authReq)));
		assertThat(mgr.authenticate(mock(Authentication.class))).isSameAs(authReq);
	}

	@Test
	public void authenticationExceptionIsRethrownIfNoLaterProviderAuthenticates()
			throws Exception {

		ProviderManager mgr = new ProviderManager(Arrays.asList(
				createProviderWhichThrows(new BadCredentialsException("")),
				createProviderWhichReturns(null)));
		try {
			mgr.authenticate(mock(Authentication.class));
			fail("Expected BadCredentialsException");
		}
		catch (BadCredentialsException expected) {
		}
	}

	// SEC-546
	@Test
	public void accountStatusExceptionPreventsCallsToSubsequentProviders()
			throws Exception {
		AuthenticationProvider iThrowAccountStatusException = createProviderWhichThrows(new AccountStatusException(
				"") {
		});
		AuthenticationProvider otherProvider = mock(AuthenticationProvider.class);

		ProviderManager authMgr = new ProviderManager(Arrays.asList(
				iThrowAccountStatusException, otherProvider));

		try {
			authMgr.authenticate(mock(Authentication.class));
			fail("Expected AccountStatusException");
		}
		catch (AccountStatusException expected) {
		}
		verifyZeroInteractions(otherProvider);
	}

	@Test
	public void parentAuthenticationIsUsedIfProvidersDontAuthenticate() throws Exception {
		AuthenticationManager parent = mock(AuthenticationManager.class);
		Authentication authReq = mock(Authentication.class);
		when(parent.authenticate(authReq)).thenReturn(authReq);
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(mock(AuthenticationProvider.class)), parent);
		assertThat(mgr.authenticate(authReq)).isSameAs(authReq);
	}

	@Test
	public void parentIsNotCalledIfAccountStatusExceptionIsThrown() throws Exception {
		AuthenticationProvider iThrowAccountStatusException = createProviderWhichThrows(new AccountStatusException(
				"", new Throwable()) {
		});
		AuthenticationManager parent = mock(AuthenticationManager.class);
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(iThrowAccountStatusException), parent);
		try {
			mgr.authenticate(mock(Authentication.class));
			fail("Expected exception");
		}
		catch (AccountStatusException expected) {
		}
		verifyZeroInteractions(parent);
	}

	@Test
	public void providerNotFoundFromParentIsIgnored() throws Exception {
		final Authentication authReq = mock(Authentication.class);
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		AuthenticationManager parent = mock(AuthenticationManager.class);
		when(parent.authenticate(authReq)).thenThrow(new ProviderNotFoundException(""));

		// Set a provider that throws an exception - this is the exception we expect to be
		// propagated
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(createProviderWhichThrows(new BadCredentialsException(""))),
				parent);
		mgr.setAuthenticationEventPublisher(publisher);

		try {
			mgr.authenticate(authReq);
			fail("Expected exception");
		}
		catch (BadCredentialsException expected) {
			verify(publisher).publishAuthenticationFailure(expected, authReq);
		}
	}

	@Test
	public void authenticationExceptionFromParentOverridesPreviousOnes() throws Exception {
		AuthenticationManager parent = mock(AuthenticationManager.class);
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(createProviderWhichThrows(new BadCredentialsException(""))),
				parent);
		final Authentication authReq = mock(Authentication.class);
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		mgr.setAuthenticationEventPublisher(publisher);
		// Set a provider that throws an exception - this is the exception we expect to be
		// propagated
		final BadCredentialsException expected = new BadCredentialsException(
				"I'm the one from the parent");
		when(parent.authenticate(authReq)).thenThrow(expected);
		try {
			mgr.authenticate(authReq);
			fail("Expected exception");
		}
		catch (BadCredentialsException e) {
			assertThat(e).isSameAs(expected);
		}
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
		}
		catch (LockedException e) {
			assertThat(e).isSameAs(expected);
		}
		verify(publisher).publishAuthenticationFailure(expected, authReq);
	}

	// SEC-2367
	@Test
	public void providerThrowsInternalAuthenticationServiceException() {
		InternalAuthenticationServiceException expected = new InternalAuthenticationServiceException(
				"Expected");
		ProviderManager mgr = new ProviderManager(Arrays.asList(
				createProviderWhichThrows(expected),
				createProviderWhichThrows(new BadCredentialsException("Oops"))), null);
		final Authentication authReq = mock(Authentication.class);

		try {
			mgr.authenticate(authReq);
			fail("Expected Exception");
		}
		catch (InternalAuthenticationServiceException success) {
		}
	}

	// gh-6281
	@Test
	public void authenticateWhenFailsInParentAndPublishesThenChildDoesNotPublish() {
		BadCredentialsException badCredentialsExParent = new BadCredentialsException("Bad Credentials in parent");
		ProviderManager parentMgr = new ProviderManager(
				Collections.singletonList(createProviderWhichThrows(badCredentialsExParent)));
		ProviderManager childMgr = new ProviderManager(Collections.singletonList(createProviderWhichThrows(
						new BadCredentialsException("Bad Credentials in child"))), parentMgr);

		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		parentMgr.setAuthenticationEventPublisher(publisher);
		childMgr.setAuthenticationEventPublisher(publisher);

		final Authentication authReq = mock(Authentication.class);

		try {
			childMgr.authenticate(authReq);
			fail("Expected exception");
		}
		catch (BadCredentialsException e) {
			assertThat(e).isSameAs(badCredentialsExParent);
		}
		verify(publisher).publishAuthenticationFailure(badCredentialsExParent, authReq);		// Parent publishes
		verifyNoMoreInteractions(publisher);		// Child should not publish (duplicate event)
	}

	private AuthenticationProvider createProviderWhichThrows(
			final AuthenticationException e) {
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
		return new TestingAuthenticationToken("name", "password",
				new ArrayList<>(0));
	}

	private ProviderManager makeProviderManager() throws Exception {
		MockProvider provider1 = new MockProvider();
		List<AuthenticationProvider> providers = new ArrayList<>();
		providers.add(provider1);

		return new ProviderManager(providers);
	}

	// ~ Inner Classes
	// ==================================================================================================

	private class MockProvider implements AuthenticationProvider {
		public Authentication authenticate(Authentication authentication)
				throws AuthenticationException {
			if (supports(authentication.getClass())) {
				return authentication;
			}
			else {
				throw new AuthenticationServiceException("Don't support this class");
			}
		}

		public boolean supports(Class<?> authentication) {
			return TestingAuthenticationToken.class.isAssignableFrom(authentication)
					|| UsernamePasswordAuthenticationToken.class
							.isAssignableFrom(authentication);
		}
	}
}
